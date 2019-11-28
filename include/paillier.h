/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

/**
 * @file paillier.h
 * @brief Paillier declarations
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ff_4096.h"
#include "ff_2048.h"

// Field size
#define FS_4096 MODBYTES_512_60*FFLEN_4096    /**< 4096 field size in bytes */
#define FS_2048 MODBYTES_1024_58*FFLEN_2048   /**< 2048 field size in bytes */

// Half field size
#define HFS_4096 MODBYTES_512_60*HFLEN_4096   /**< Half 4096 field size in bytes */
#define HFS_2048 MODBYTES_1024_58*HFLEN_2048  /**< Half 2048 field size in bytes */

/*!
 * \brief Paillier Public Key
 */
typedef struct{
    BIG_512_60 n[FFLEN_4096]; /**< Paillier Modulus - n = pq */
    BIG_512_60 g[FFLEN_4096]; /**< Public Base - n+1 */

    BIG_512_60 n2[FFLEN_4096]; /**< Precomputed n^2 */
}PAILLIER_public_key;

/*!
 * \brief Paillier Private Key
 */
typedef struct{
    BIG_512_60 n[FFLEN_4096]; /**< Paillier Modulus - n = pq*/
    BIG_512_60 g[FFLEN_4096]; /**< Public Base - n+1 */
    BIG_512_60 l[FFLEN_4096]; /**< Private Key (Euler totient of n) */
    BIG_512_60 m[FFLEN_4096]; /**< Precomputed l^(-1) */

    BIG_512_60 p[HFLEN_4096];  /**< Secret Prime */
    BIG_512_60 q[HFLEN_4096];  /**< Secret Prime */
    BIG_512_60 n2[FFLEN_4096]; /**< Precomputed n^2 */
}PAILLIER_private_key;

/*! \brief Generate the key pair
 *
 *  Pick large prime numbers of the same size \f$ p \f$ and \f$ q \f$
 *
 *  <ol>
 *  <li> \f$ n = pq \f$
 *  <li> \f$ g = n + 1 \f$
 *  <li> \f$ l = (p-1)(q-1) \f$
 *  <li> \f$ m = l^{-1} \pmod{n} \f$
 *  </ol>
 *
 *  @param  RNG              Pointer to a cryptographically secure random number generator
 *  @param  P                Prime number. If RNG is NULL then this value is read
 *  @param  Q                Prime number. If RNG is NULL then this value is read
 *  @param  PUB              Public key
 *  @param  PRIV             Private key
 */
void PAILLIER_KEY_PAIR(csprng *RNG, octet *P, octet* Q, PAILLIER_public_key *PUB, PAILLIER_private_key *PRIV);

/*! \brief Clear private key
 *
 *  @param PRIV             Private key to clean
 */
void PAILLIER_PRIVATE_KEY_KILL(PAILLIER_private_key *PRIV);

/*! \brief Encrypt a plaintext
 *
 *  These are the encryption steps.
 *
 *  <ol>
 *  <li> \f$ m < n \f$
 *  <li> \f$ r < n \f$
 *  <li> \f$ c = g^m.r^n\pmod{n^2} \f$
 *  </ol>
 *
 *  @param  RNG              Pointer to a cryptographically secure random number generator
 *  @param  PUB              Public key
 *  @param  PT               Plaintext
 *  @param  CT               Ciphertext
 *  @param  R                R value for testing. If RNG is NULL then this value is read.
 */
void PAILLIER_ENCRYPT(csprng *RNG, PAILLIER_public_key *PUB, octet* PT, octet* CT, octet* R);

/*! \brief Decrypt ciphertext
 *
 *  These are the decryption steps.
 *
 *  <ol>
 *  <li> \f$ n2  = n*n \f$
 *  <li> \f$ ctl = ct^l \pmod{n2} - 1 \f$
 *  <li> \f$ ctln = ctl / n \f$
 *  <li> \f$ pt = ctln * m \pmod{n} \f$
 *  </ol>
 *
 *  @param   PRIV             Private key
 *  @param   CT               Ciphertext
 *  @param   PT               Plaintext
 */
void PAILLIER_DECRYPT(PAILLIER_private_key *PRIV, octet* CT, octet* PT);

/*! \brief Homomorphic addition of plaintexts
 *
 *  \f$ E(m1+m2) = E(m1)*E(m2) \f$
 *
 *  <ol>
 *  <li> \f$ ct = ct1*ct2 \pmod{n^2} \f$
 *  </ol>
 *
 *  @param   PUB              Public key
 *  @param   CT1              Ciphertext one
 *  @param   CT2              Ciphertext two
 *  @param   CT               Ciphertext
 *  @return                   Returns 0 or else error code
 */
void PAILLIER_ADD(PAILLIER_public_key *PUB, octet* CT1, octet* CT2, octet* CT);

/*! \brief Homomorphic multipication of plaintexts
 *
 *  \f$ E(m1*m2) = E(m1)^{m2} \f$
 *
 *  <ol>
 *  <li> \f$ ct = ct1^{m2} \pmod{n^2} \f$
 *  </ol>
 *
 *  @param   PUB              Public key
 *  @param   CT1              Ciphertext one
 *  @param   PT               Plaintext constant
 *  @param   CT               Ciphertext
 */
void PAILLIER_MULT(PAILLIER_public_key *PUB, octet* CT1, octet* PT, octet* CT);
