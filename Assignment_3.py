"""Solution to Assignment 3.

Python version 3.9 or later.

Your final submission must contain the following functions:
    - brute_force_dl(mod, gen, order, target)
    - baby_step_giant_step_dl(mod, gen, order, target):
    - crt(vals, mods)
    - pohlig_hellman(mod, gen, factors, target)
    - elgamal_attack(params, pk)
"""
import math
from itertools import combinations


def brute_force_dl(mod, gen, order, target):
    """Uses brute force to compute discrete log of target with respect to gen.

    Parameters:
        mod (int): The prime modulus over which computation is carried out.
        gen (int): An element of Z*_mod.
        order (int): The order of the subgroup generated by gen.
        target (int): The element whose discrete log is to be computed.

    Returns:
        int: The discrete log of target with respect to gen.
    """
    for x in range(order):
        if pow(gen, x, mod) == target:
            return x
    return 0


def baby_step_giant_step_dl(mod, gen, order, target):
    """Uses the baby step giant step algorithm to compute discrete log of
    target with respect to gen.

    Parameters:
        mod (int): The prime modulus over which computation is carried out.
        gen (int): An element of Z*_mod.
        order (int): The order of the subgroup generated by gen.
        target (int): The element whose discrete log is to be computed.

    Returns:
        int: The discrete log of target with respect to gen.
    """
    # Calculate m as square root of order, and take value up to one.
    m = 1 + math.isqrt(order)

    # Calculate baby-step list.
    baby_steps = {}
    temp = 1
    for i in range(m):
        baby_steps[temp] = i
        temp = (temp * gen) % mod
        #baby_steps[pow(gen, i, mod)] = i

    # Compute giant-step and find a match.
    giant_step = pow(gen, -m, mod)
    t = target
    for j in range(m):
        # Check if the target is matched in BS list.
        if t in baby_steps:
            return j * m + baby_steps[t]
        t = (t * giant_step) % mod

    return 0


def crt(vals, mods):
    """Solves a system of congruences.

    Parameters:
        vals (list(int)): A list of values.
        mods (list(int)): A list of moduli which are pairwise coprime i.e., mod[i] and mod[j] are
            coprime for any i ≠ j. The length of this list is equal to that of vals.

    Returns:
        int: An integer z such that for every i in {0, .., len(vals) - 1}, z ≡ vals[i] mod mods[i].
    """
    # Calculate product for all m1 m2 m3 ... => M
    M = 1
    for mod in mods:
        M = M * mod

    # Loop through every congruence equation to find a match.
    ret = 0
    for i in range(len(vals)):
        a_curr = vals[i]
        m_curr = mods[i]
        M_curr = M // m_curr
        value  = a_curr * M_curr * pow(M_curr, -1, m_curr)
        ret = ret + value
    ret = ret % M

    return ret


def pohlig_hellman(mod, gen, factors, target):
    """Uses the Pohlig-Hellman algorithm to compute discrete log of target with
    respect to gen, given the factorization of the order of the subgroup
    generated by gen.

    Parameters:
        mod (int): The prime modulus over which computation is carried out.
        gen (int): An element of Z*_mod.
        factors (list(int, int)): A list of values [(p_1, e_1), ..., (p_n, e_n)] such that the order
            of the subgroup generated by gen is p_1^{e_1} * ... * p_n^{e_n}.
        target (int): The element whose discrete log is to be computed.

    Returns:
        int: The discrete log of target with respect to gen.
    """
    vals = []
    mods = []

    # Calculate order.
    q = mod - 1

    # Calculate p_i^e_i.
    for p_i, e_i in factors:
        t = target
        value = 0
        g_i = pow(gen, q // p_i, mod)  # g^(q/p) mod mod
        g_i_inv = pow(gen, -1, mod)
        pk = 1  # p^k

        # 1
        if e_i == 1:
            x_i = baby_step_giant_step_dl(mod, pow(gen, q // (p_i ** e_i), mod), p_i, pow(t, q // (p_i ** e_i), mod))
            vals.append(x_i)
            mods.append(p_i ** e_i)
        # 2
        else:
            for j in range(e_i):
                h_i = pow(t, q // (p_i ** (j + 1)), mod)
                x_i = baby_step_giant_step_dl(mod, g_i, p_i, h_i)
                value += x_i * pk

                if x_i != 0:
                    g_i_inv_pk = pow(g_i_inv, pk, mod)
                    t = (t * pow(g_i_inv_pk, x_i, mod)) % mod
                pk = pk * p_i

            value = value % (p_i ** e_i)
            vals.append(value)
            mods.append(p_i ** e_i)

    ret = crt(vals, mods)
    return ret

def elgamal_attack(params, pk):
    """
    Given an ElGamal public key in Z*_mod, where mod is prime, recovers the corresponding secret
    key when mod - 1 has sufficiently many 'small' prime factors.

    Parameters:
        params (Params): ElGamal parameters. It is an instance of the Params class defined in
            problem.py.
        pk (int): The ElGamal public key. It is guaranteed that the corresponding secret key is
            less than params.exp_bound.

    Returns:
        int: The discrete log of pk with respect to gen.
    """
    # Attempt-1 : List all possible subgroup and find suitable.
    #p, g, factors, exp_bound = params.mod, params.gen, params.factors, params.exp_bound
    #factors.sort(key=lambda f: f[0] ** f[1], reverse=True) # Sort based on order, from big to small.
    # best_factors = []
    # best_order = 1
    # all_combinations = []
    # for r in range(1, len(factors) + 1):
    #     for subset in combinations(factors, r):
    #         subgroup_order = 1
    #         for p_i, e_i in subset:
    #             subgroup_order *= (p_i ** e_i)
    #         all_combinations.append((subset, subgroup_order))
    #
    #     all_combinations.sort(key=lambda x: x[1], reverse=True)
    #     for subset, subgroup_order in all_combinations:
    #         if subgroup_order < exp_bound:
    #             best_factors = subset
    #             best_order = subgroup_order
    #             break
    #         # if subgroup_order < 2**128 and subgroup_order > best_order:
    #         #     best_factors = subset
    #         #     best_order = subgroup_order
    # if best_order < exp_bound: return 0
    # sk = pohlig_hellman(p, pow(g, (p - 1) // best_order, p), best_factors, pow(pk, (p - 1) // best_order, p))

    p, g, factors, exp_bound = params.mod, params.gen, params.factors, params.exp_bound
    #factors.sort(key=lambda f: f[0] ** f[1], reverse=True)  # Sorting factors from big to small.
    subgroup_factors = []
    subgroup_order = 1

    # Attempt-3
    for p_i, e_i in factors:
        subgroup_order = subgroup_order * (p_i ** e_i)
        subgroup_factors.append((p_i, e_i))

        if subgroup_order >= exp_bound:
            break


    # Attempt-2
    # for p_i, e_i in factors:
    #     if subgroup_order * (p_i ** e_i) >= exp_bound:
    #         subgroup_factors.append((p_i, e_i))
    #         subgroup_order *= factor_value
    #         break
    #     else:
    #         subgroup_factors.append((p_i, e_i))
    #         subgroup_order *= factor_value

    # if subgroup_order < exp_bound: return 0
    #     raise ValueError("Could not find a smooth subgroup of order >= 2^128.")

    sk = pohlig_hellman(p, pow(g, (p - 1) // subgroup_order, p), subgroup_factors, pow(pk, (p - 1) // subgroup_order, p))
    return sk
