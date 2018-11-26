# -*- coding: utf-8 -*-

from __future__ import print_function

"""
LELEC2770 : Privacy Enhancing Technologies

Exercice Session : Secure 2-party computation

Paper - Rock - Scissors
"""

import six
from six.moves import input
from Crypto.Random import random

from logic_circuit import Gate, Circuit, INPUT_GATE
# from garbled_circuit import garble_circuit, evaluate_garbled_circuit
from garbled_circuit_freexor import garble_circuit, evaluate_garbled_circuit

prs_circuit = Circuit(
    {
        "A": INPUT_GATE,
        "B": INPUT_GATE,
        "C": INPUT_GATE,
        "D": INPUT_GATE,
        "AB": Gate("AND", "A", "B"),
        "AC": Gate("AND", "A", "C"),
        "BC": Gate("AND", "B", "C"),
        "BxC": Gate("XOR", "B", "C"),
        "BD": Gate("AND", "B", "D"),
        "CD": Gate("AND", "C", "D"),
        "AD": Gate("AND", "A", "D"),
        "AxD": Gate("XOR", "A", "D"),
        "ACxBD": Gate("XOR", "AC", "BD"),
        "BCxCD": Gate("XOR", "BC", "CD"),
        "ABxAD": Gate("XOR", "AB", "AD"),
        "ACxBDxBCxCD": Gate("XOR", "ACxBD", "BCxCD"),
        "ACxBDxABxAD": Gate("XOR", "ACxBD", "ABxAD"),
        "E": Gate("XOR", "ACxBDxABxAD", "BxC"),
        "F": Gate("XOR", "ACxBDxBCxCD", "AxD"),
    },
    {"E", "F"},
)


def choice_to_bin(choice):
    if choice in ["PAPER", "P"]:
        return 0, 0
    elif choice in ["ROCK", "R"]:
        return 1, 0
    elif choice in ["SCISSORS", "S"]:
        return 0, 1
    elif choice in ["LOSE", "L"]:
        return 1, 1


def prs_result(E, F):
    if (E, F) == (0, 0):
        return "draw"
    elif (E, F) == (0, 1):
        return "Bob wins"
    elif (E, F) == (1, 0):
        return "Alice wins"
    else:
        raise ValueError((E, F))


def test_prs_circuit():
    inputs = {"P": (0, 0), "R": (1, 0), "S": (0, 1), "L": (1, 1)}
    for ai_n, ai in six.iteritems(inputs):
        for bi_n, bi in six.iteritems(inputs):
            input_all = {"A": ai[0], "B": ai[1], "C": bi[0], "D": bi[1]}
            res = prs_circuit.evaluate(input_all).state
            res = res["E"], res["F"]
            print(ai_n, bi_n, prs_result(*res))


def run_garbled_prs():
    # Alice's inputs are A,B chosen randomly
    alice_input = {"A": random.getrandbits(1), "B": random.getrandbits(1)}

    Bob_choice = None
    while Bob_choice not in ["PAPER", "ROCK", "SCISSORS", "LOSE", "P", "R", "S", "L"]:
        Bob_choice = input(
            "Bob'choice is PAPER (P), ROCK (R), SCISSORS (S) or LOSE (L) : "
        )
    C, D = choice_to_bin(Bob_choice)
    bob_input = {"C": C, "D": D}

    # @students: Who runs the next line ? Alice or Bob ? (and is the other
    # party involved in a sub-step ?)
    garbled_circuit, input_keys, ot_senders = garble_circuit(prs_circuit, alice_input)
    # @students: Who runs the next line ? Alice or Bob ? (and is the other
    # party involved in a sub-step ?)
    circuit_state = evaluate_garbled_circuit(
        prs_circuit, bob_input, garbled_circuit, input_keys, ot_senders
    )
    print(prs_result(circuit_state["E"], circuit_state["F"]))

    # Compare garbled evaluation against direct evaluation.
    input_all = alice_input.copy()
    input_all.update(bob_input)
    ref_res = prs_circuit.evaluate(input_all).state
    assert (ref_res['E'], ref_res['F']) == (circuit_state['E'],
            circuit_state['F'])


if __name__ == "__main__":
    #test_prs_circuit()
    run_garbled_prs()
