# -*- coding: utf-8 -*-

from __future__ import print_function

"""
LELEC2770 : Privacy Enhancing Technologies

Exercice Session : Secure 2-party computation

Logic Circuit
"""

import six


class Gate:
    """Binary logic gate or input gate

    :param kind: "INPUT", "AND", "NAND", "OR", "NOR" or "XOR"
    :param in0_id: id of the gate connected to the first input. None for an
        input gate.
    :param in1_id: id of the gate connected to the second input. None for an
        input gate.
    """

    KINDS = ("INPUT", "AND", "NAND", "OR", "NOR", "XOR")

    def __init__(self, kind, in0_id, in1_id):
        assert kind in self.KINDS
        assert kind != "INPUT" or (in0_id is None and in1_id is None)
        self.kind = kind
        self.in0_id = in0_id
        self.in1_id = in1_id

    @classmethod
    def compute_gate(cls, kind, in1, in2):
        """Compute the output of a gate given its kind and the values at its
        input.
        """
        assert kind in cls.KINDS and kind != "INPUT"
        if kind == "AND":
            return in1 and in2
        elif kind == "NAND":
            return not (in1 and in2)
        elif kind == "OR":
            return in1 or in2
        elif kind == "NOR":
            return not (in1 or in2)
        elif kind == "XOR":
            return in1 ^ in2
        else:
            assert False


# All input gates are identical, hence this constant can be used as a shortcut.
INPUT_GATE = Gate("INPUT", None, None)


class Circuit:
    """Logic circuit

    :param g: representation of the circuit
    :param output_gates: ids of output gates
    :type g: dictionnary {gate_id, Gate}
    :type output_gates: set of ids
    """

    def __init__(self, g, output_gates):
        self.g = g
        self.output_gates = output_gates

    def evaluate(self, input_vals):
        """Evaluate logic circuit

        :param input_vals: values at the input of the circuit
        :type input_vals: dictionnary {input_gate_id: 0/1}

        :return: Circuit evalutation
        :rtype: CircuitEvaluation
        """
        for g_id, gate in six.iteritems(self.g):
            assert gate.kind != "INPUT" or g_id in input_vals
        for g_id in input_vals:
            assert self.g[g_id].kind == "INPUT"
        return CircuitEvaluation(self, input_vals)

    # ADDED FOR FREEXOR
    def ordered_gates(self):
        all_keys = self.g.keys()
        ordered = [i for i in all_keys if self.g[i].kind == "INPUT"]

        all_keys = [x for x in all_keys if x not in ordered]

        while all_keys != []:
            for key in all_keys:
                if self.g[key].in0_id in ordered and self.g[key].in1_id in ordered:
                    ordered.append(key)
                    all_keys.remove(key)

        return ordered


class CircuitEvaluation:
    """CircuitEvaluation

    Object created by Circuit.evaluate.
    The state attribute is a dictionnary
    {gate_id: value_at_output_of_the_gate}.
    """

    def __init__(self, circuit, input_vals):
        self.state = input_vals.copy()
        self.circuit = circuit
        for g_id in self.circuit.output_gates:
            self._recursive_evaluate(g_id)

    def _recursive_evaluate(self, g_id):
        if g_id in self.state:
            return self.state[g_id]
        else:
            in0_id = self.circuit.g[g_id].in0_id
            in1_id = self.circuit.g[g_id].in1_id
            kind = self.circuit.g[g_id].kind
            in1 = self._recursive_evaluate(in0_id)
            in2 = self._recursive_evaluate(in1_id)
            res = Gate.compute_gate(kind, in1, in2)
            self.state[g_id] = res
            return res


def test_circuit():
    """A simple test circuit"""
    circ = Circuit(
        {
            0: INPUT_GATE,
            1: INPUT_GATE,
            2: INPUT_GATE,
            3: Gate("AND", 0, 1),
            4: Gate("XOR", 2, 3),
        },
        {4},
    )
    circ_eval = circ.evaluate({0: 1, 1: 1, 2: 0})
    assert circ_eval.state == {0: 1, 1: 1, 2: 0, 3: 1, 4: 1}
    # print('Output of test circuit is', circ_eval.state[4])


if __name__ == "__main__":
    test_circuit()
