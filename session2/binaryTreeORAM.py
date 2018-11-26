# -*- coding: utf-8 -*-
"""
LELEC2770 : Privacy Enhancing Technologies

Exercice Session : ORAM

Binary tree ORAM
"""

from __future__ import print_function, division
import random


class SuperCryptoSystem:
    """A very efficient AEAD scheme (we need CCA security !)"""
    def __init__(self, key=0):
        self.key = key

    def enc(self, data):
        """
        Never do this at home for your safety
        """
        return data

    def dec(self, data):
        """
        see, crypto is easy
        """
        return data


class Client:
    """
    Client representing the client knowledge
    """

    def __init__(self, server, crypto, tree_depth, bucket_size):
        self.pos = {}
        self.server = server
        self.crypto = crypto
        self.tree_depth = tree_depth
        self.bucket_size = bucket_size
        self.capacity = 2**(tree_depth)
        for addr in range(self.capacity):
            self._insert_block_at_root(addr, 0)

    def query(self, addr, write_data=None):
        """
        Performs a Binary Tree ORAM access
        @addr memory address
        @write_data data to write (if None, previous data is preserved)
        @return data element matching @addr
        """
        assert addr in range(self.capacity), "You're trying to read uninitialized memory !"
        assert addr in self.pos
        leaf_id = self.pos[addr]
        path = BinaryTree.path_to_leaf(leaf_id)
        res_data = None
        # <To be done by students>
        # walk through the path, for each block in each bucket read en
        #re-encrypt, except for data at addr, for which re-encrypt None and put
        #the data in res_data
        if write_data is None:
            for node_id in path:
                for block_id in range(self.bucket_size):
                    r = self.server.read(node_id, block_id)
                    d = self.crypto.dec(r)
                    if d is not None:
                        dec_addr, data = d
                        if addr == dec_addr:
                            res_data = data
                            self.server.write(node_id, block_id, self.crypto.enc(None))
                    else:
                        self.server.write(node_id, block_id, self.crypto.enc(d))
        # </To be done by students>
        self._insert_block_at_root(addr, write_data if write_data is not None else res_data)
        return res_data

    def _insert_block_at_root(self, addr, data):
        self.pos[addr] = random.choice(BinaryTree.leafs_ids(self.tree_depth))
        new_block_idx = None
        for i in range(self.bucket_size):
            dec_block = self.crypto.dec(self.server.read(BinaryTree.root_id(), i))
            if dec_block is None:
                new_block_idx = i
        assert new_block_idx is not None, "Congestion at the root"
        new_block = self.crypto.enc((addr, data))
        self.server.write(BinaryTree.root_id(), new_block_idx, new_block)
        self.evict()

    def evict(self):
        self._evict_bucket(BinaryTree.root_id())
        for depth in range(1, self.tree_depth):
            # select two random nodes
            nodes = BinaryTree.nodes_at_depth(depth)
            random.shuffle(nodes)
            nodes = nodes[:2]
            for node in nodes:
                self._evict_bucket(node)

    def _evict_bucket(self, node_id):
        found_address = None
        found_data = None
        for i in range(self.bucket_size):
            dec_block = self.crypto.dec(self.server.read(node_id, i))
            if dec_block is not None and found_address is None:
                found_address, found_data = dec_block
                self.server.write(node_id, i, self.crypto.enc(None))
            else:
                self.server.write(node_id, i, self.crypto.enc(dec_block))
        left_child = BinaryTree.left_child(node_id, self.tree_depth)
        right_child = BinaryTree.right_child(node_id, self.tree_depth)
        if found_address is None:
            block_to_insert_left = None
            block_to_insert_right = None
        else:
            pos = self.pos[found_address]
            path = BinaryTree.path_to_leaf(pos)
            found_block = None if found_address is None else (found_address, found_data)
            block_to_insert_left = found_block if left_child in path else None
            block_to_insert_right = found_block if right_child in path else None
        # process left child
        self._child_insert(left_child, block_to_insert_left)
        self._child_insert(right_child, block_to_insert_right)

    def _child_insert(self, child_id, block_to_insert):
        for i in range(self.bucket_size):
            dec_block = self.crypto.dec(self.server.read(child_id, i))
            if dec_block is None and block_to_insert is not None:
                self.server.write(child_id, i, self.crypto.enc(block_to_insert))
                block_to_insert = None
            else:
                self.server.write(child_id, i, self.crypto.enc(dec_block))
        assert block_to_insert is None, "Congestion at node {}".format(child_id)


class BigStorageServer:
    """(Unstrusted) Backend storage server, with a simple API: it has a fixed
    number of buckets, that each contain a fixed number of blocks, with
    read/write access to each block.
    All blocks are initialized as None.
    """
    def __init__(self, nb_buckets, bucket_size):
        self.storage = [bucket_size*[None] for _ in range(nb_buckets)]

    def read(self, bucket_id, block_id):
        return self.storage[bucket_id][block_id]

    def write(self, bucket_id, block_id, value):
        self.storage[bucket_id][block_id] = value


class BinaryTree:
    """A simple stateless perfect binary tree (see
    <https://en.wikipedia.org/wiki/Binary_tree#Arrays>),
    the node ids are guaranteed to be in the range [0, nbr_nodes[.
    Valid node depths are 0 (root) to tree_depth (leafs)"""
    @staticmethod
    def path_to_leaf(leaf_id):
        node_id = leaf_id
        path = [node_id]
        while True:
            parent_id = BinaryTree.parent(node_id)
            if parent_id is None:
                path.reverse()
                return path
            else:
                node_id = parent_id
                path.append(node_id)

    @staticmethod
    def nodes_at_depth(depth):
        """List of all the node_ids at depth @depth"""
        return list(range(2**depth-1, 2**(depth+1)-1))

    @classmethod
    def leafs_ids(cls, tree_depth):
        """List of all the leafs"""
        return cls.nodes_at_depth(tree_depth)

    @staticmethod
    def nbr_nodes(tree_depth):
        """Number of nodes in the tree."""
        return 2**(tree_depth+1)-1

    @staticmethod
    def root_id():
        return 0

    @staticmethod
    def parent(node_id):
        if node_id == 0:
            return None
        else:
            return (node_id-1) // 2

    @staticmethod
    def left_child(node_id, tree_depth):
        res = 2*node_id + 1
        if res >= BinaryTree.nbr_nodes(tree_depth):
            return None
        else:
            return res

    @staticmethod
    def right_child(node_id, tree_depth):
        res = 2*node_id + 2
        if res >= BinaryTree.nbr_nodes(tree_depth):
            return None
        else:
            return res

def test(client, nbr_test=10**3):
    capacity = client.capacity
    addresses = list(range(capacity))
    state = capacity*[0]
    for i in range(nbr_test):
        # write test
        addr = random.choice(addresses)
        client.query(addr, write_data=i+1)
        state[addr] = i+1
        # read test
        addr = random.choice(addresses)
        r1 = client.query(addr)
        assert r1 == state[addr]
    print("It's working ! Nice job -;)")

if __name__ == "__main__":

    tree_depth = 10
    bucket_size = 15
    nb_buckets = BinaryTree.nbr_nodes(tree_depth)
    server = BigStorageServer(nb_buckets, bucket_size)
    crypto = SuperCryptoSystem()
    client = Client(server, crypto, tree_depth, bucket_size)

    test(client)
