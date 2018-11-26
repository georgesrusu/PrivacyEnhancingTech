#!/usr/bin/env python
import json
from pybots import HTTPBot
from tinyscript import *


class Oracle(HTTPBot):
    url = "https://lelec2770.pythonanywhere.com/elections1"

    def __init__(self, **kwargs):
        super(Oracle, self).__init__(self.url, **kwargs)

    def submit(self, c1, c2):
        """
        Submit a ciphertext to the oracle to get the plaintext.
        
        :param c1: first ciphertext's number
        :param c2: second ciphertext's number
        """
        self.get()
        # retrieve hidden form values
        formkey = self.soup.find('input', {'name': "_formkey"}).get('value')
        self.logger.debug("_formkey = {}".format(formkey))
        formname = self.soup.find('input', {'name': "_formname"}).get('value')
        self.logger.debug("_formname = {}".format(formname))
        self.post(json={'ciphertext': "{\"c1\":%d,\"c2\":%d}" % (c1, c2),
                        '_formkey': formkey, '_formname': formname})
        if "Plaintext" not in self.response.text:
            self.logger.error("FAILED")
        else:
            h2 = self.soup.body.find(text=re.compile("Plaintext"))
            return h2.find_next("div").text


class Votes(object):
    """
    This class handles a JSON file containing encrypted votes.
    
    :param filename: JSON filename
    """
    def __init__(self, filename):
        logger.debug("Parsing the input data...")
        self.__cache = {}
        self.__data = json.load(open(filename))
        self.filename = filename
        self.oracle = Oracle()
        self.p = self.__data['p']
        self.q = self.__data['q']
        self.g = self.__data['g']
        self.h = self.__data['h']
        self.votes = self.__data['ciphertexts']
    
    def __get_users(self, n=2, exclude=()):
        """
        Get random user indices.
        
        :param n:       number of users to be sampled
        :param exclude: indices that cannot be matched
        """
        logger.debug("Getting random users...")
        users = random.sample(range(0, len(self.votes) - 1), n)
        while any(u in users for u in exclude):
            users = random.sample(range(0, len(self.votes) - 1), n)
        return users
    
    def __global_ciphertext(self, *users):
        """
        Compute the global ciphertext by the multiplication of the (c1, c2) of
         the given users.
         
        :param users: list of user indices
        """
        assert all(0 <= u < len(self.votes) for u in users)
        logger.debug("Computing the global ciphertext...")
        users = [self.votes[u] for u in users]
        if len(users) == 0:
            users = self.votes
        c1, c2 = 1, 1
        for u in users:
            c1 = (c1 * u['c1']) % self.p
            c2 = (c2 * u['c2']) % self.p
        return c1, c2
    
    def __unveil_vote(self, user, ref1=None, ref2=None):
        """
        Unveil the vote of a given user using two other reference ones.
        
        :param user: user of which the vote is to be revealed
        :param ref1: first reference vote
        :param ref2: second reference vote
        """
        if ref1 is None:
            ref1 = self.__get_users(1, (user, ref2))[0]
        if ref2 is None:
            ref2 = self.__get_users(1, (user, ref1))[0]
        c1, c2 = self.__global_ciphertext(user, ref1, ref2)
        r = int(self.oracle.submit(c1, c2))
        k = (ref1, ref2)
        if k in self.__cache.keys():
            c1, c2 = self.__cache[k]
        else:
            c1, c2 = self.__global_ciphertext(*k)
            self.__cache[k] = c1, c2
        return r - int(self.oracle.submit(c1, c2))
    
    def result(self):
        """
        Get the election result by submitting the global ciphertext of all the
         users' votes to the bound decryption oracle.
        """
        logger.debug("Getting the election result...")
        if not hasattr(self, "_result"):
            self._result = self.oracle.submit(*self.__global_ciphertext())
        logger.info(self._result)
        return self
    
    def unveil(self, user=None):
        """
        Unveil given user's vote or unveil the votes of every user if no user
         index is given.
        
        :param user: user index
        """
        l = len(self.votes)
        assert user is None or 0 <= user < l
        # unveil given user's vote if a user index was given
        if user is not None:
            v = self.__unveil_vote(user)
            logger.info("User#{}'s vote: {}".format(user, v))
        # otherwise, unveil all votes
        else:
            fn, _ = os.path.splitext(self.filename)
            fn = "{}-unveiled.txt".format(fn)
            s = 0
            # restart from previous results
            if os.path.exists(fn):
                with open(fn) as f:
                    for s, _ in enumerate(f):
                        pass
            # append new results
            with open(fn, 'ab+') as f:
                ur1, ur2 = l - 2, l - 1
                for i in range(s, len(self.votes)):
                    if i == l // 2:
                        ur1, ur2 = 0, 1
                    f.write(str(self.__unveil_vote(i, ur1, ur2)) + '\n')
            logger.info("Users' votes dumped to '{}'".format(fn))


if __name__ == '__main__':
    parser.add_argument("--votes", default="votes1.json",
                        help="JSON with encrypted votes")
    initialize(globals())
    Votes(args.votes).result().unveil()
