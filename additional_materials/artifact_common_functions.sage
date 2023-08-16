# -*- coding: utf8 -*-
import os
import sys
import pickle
import tqdm

module_path = os.path.abspath("../../../..")

if module_path not in sys.path:
    sys.path.append(module_path)

import dilithium_functions as dilithium

import matplotlib.pyplot as plt
import math
import time 
import copy as py_copy
from binascii import unhexlify, hexlify
from collections import Counter
import random as py_random
import numpy as np 
from scipy.linalg import toeplitz

from sage.all import *

np_remainder = np.vectorize(math.remainder)

def negacyclic(vec):
    """
    Generates the negacyclic matrix whose first column is vec
    Input: vec (n-array)
    Output: mat (nxn-array)
    """ 
    row = np.zeros(len(vec))
    row[0] = vec[0]
    row[1:] = -vec[-1:0:-1]
    return toeplitz(vec, row).astype(int)


def Antt2Aintt(A):
    """
    Converts the matrix A in the normal domain 
    Input: A(n-array) in NTT domain
    Output: A(nxn-array) in normal domain
    """
    A_intt_ = []
    for i in range(dilithium.K):
        A_k = []
        for j in range(dilithium.L):
            a_test = py_copy.deepcopy(A[i][j])
            dilithium.poly_reduce(a_test)
            dilithium.invntt_frominvmont(a_test)
            A_k.append(a_test)
        A_intt_.append(A_k)
    return [[[dilithium.montgomery_reduce(a) for a in al] for al in ak]for ak in A_intt_]


def sign2poly(sm, pk):

    """
    Returns the polynomials from a given signature and public key
    Input: sm(hex str) a Dilithium signature
    Output: pk(hex str) a Dilithium pk
    """
    rho, t1 = dilithium.unpack_pk(pk)

    z = []
    h = [0]*dilithium.K
    seed = bytearray()

    if(dilithium.unpack_sig(z, h, seed, sm)):
        print("Problem in the signature")
        return -1
    if (dilithium.polyvecl_chknorm(z, dilithium.GAMMA1 - dilithium.BETA)):
        print("Problem in the public key")
        return -1

    # Sample the challenge C
    c = dilithium.challenge(unhexlify(seed.decode()))
    c_coeffs = np.array(c, dtype = int)
    
    # Construct the negacyclic matrix associated with c
    C = negacyclic(c_coeffs)
    CS = matrix(ZQ, C)

    # A is expanded in NTT domain
    Antt = dilithium.polyvec_matrix_expand(rho)
    # We convert A back in normal domain
    A = Antt2Aintt(Antt)

    # matrix A as a polynomial of R_q
    poly_A = matrix(R, A)

    # vector c as a polynomial of R_q
    poly_c = R(c)

    # vector z as a polynomila of R_q
    poly_z = vector(R, z)

    # vector z as a polynomila of R_q
    poly_t1 = vector(R, t1)

    # Value used in the verification
    poly_Az_ct12d = poly_A*poly_z - poly_c*poly_t1*pow(2, dilithium.D)

    Az_ct12d = [list(poly_Az_ct12d[i]) for i in range(dilithium.K)]
    w1 = dilithium.polyveck_use_hint(Az_ct12d, h)

    poly_w1 = vector(R, w1)

    # We return the sensitive val together with the matrix C 
    return poly_Az_ct12d - poly_w1*dilithium.ALPHA, CS




# Instanciate the polynomial ring used
ZQ = IntegerModRing(dilithium.Q)
ZQX = PolynomialRing(ZQ, "x")
x = ZQX.gen()
R = ZQX.quotient(x**dilithium.N + 1, "x")