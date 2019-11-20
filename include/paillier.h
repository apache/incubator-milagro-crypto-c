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
#include "ff_8192.h"
#include "ff_4096.h"
#include "ff_2048.h"

#define HASH_TYPE SHA256  /**< Hash function used */

// Field size
#define FS_8192 MODBYTES_512_60*FFLEN_8192    /**< 8192 field size in bytes */
#define FS_4096 MODBYTES_512_60*FFLEN_4096    /**< 4096 field size in bytes */
#define FS_2048 MODBYTES_1024_58*FFLEN_2048   /**< 2048 field size in bytes */

// Half field size
#define HFS_8192 MODBYTES_512_60*HFLEN_8192   /**< Half 8192 field size in bytes */
#define HFS_4096 MODBYTES_512_60*HFLEN_4096   /**< Half 4096 field size in bytes */
#define HFS_2048 MODBYTES_1024_58*HFLEN_2048  /**< Half 2048 field size in bytes */

/*! \brief quotient of y divided by x
 *
 *  <ol>
 *  <li> \f$ z = y / x \f$
 *  </ol>
 *
 *  @param  x       Demominator
 *  @param  y       Numerator
 *  @param  z       Quotient of y divided by x
 *  @return         Returns 0 or else error code
 */
int FF_4096_divide(BIG_512_60 x[], BIG_512_60 y[], BIG_512_60 z[]);

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
 *  @param  N                Public key (see above)
 *  @param  G                Public key (see above)
 *  @param  L                Private key (see above)
 *  @param  M                Private key (see above)
 *  @return                  Returns 0 or else error code
 */
int PAILLIER_KEY_PAIR(csprng *RNG, octet *P, octet* Q, octet* N, octet* G, octet* L, octet* M);

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
 *  @param  N                Public key
 *  @param  G                Public key (see above)
 *  @param  PT               Plaintext
 *  @param  CT               Ciphertext
 *  @param  R                R value for testing. If RNG is NULL then this value is read.
 *  @return                  Returns 0 or else error code
 */
int PAILLIER_ENCRYPT(csprng *RNG, octet* N, octet* G, octet* PT, octet* CT, octet* R);

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
 *  @param   N                Public key
 *  @param   L                Private key (see above)
 *  @param   M                Private key (see above)
 *  @param   CT               Ciphertext
 *  @param   PT               Plaintext
 *  @return                   Returns 0 or else error code
 */
int PAILLIER_DECRYPT(octet* N, octet* L, octet* M, octet* CT, octet* PT);

/*! \brief Homomorphic addition of plaintexts
 *
 *  \f$ E(m1+m2) = E(m1)*E(m2) \f$
 *
 *  <ol>
 *  <li> \f$ ct = ct1*ct2 \pmod{n^2} \f$
 *  </ol>
 *
 *  @param   N                Public key
 *  @param   CT1              Ciphertext one
 *  @param   CT2              Ciphertext two
 *  @param   CT               Ciphertext
 *  @return                   Returns 0 or else error code
 */
int PAILLIER_ADD(octet* N, octet* CT1, octet* CT2, octet* CT);

/*! \brief Homomorphic multipication of plaintexts
 *
 *  \f$ E(m1*m2) = E(m1)^{m2} \f$
 *
 *  <ol>
 *  <li> \f$ ct = ct1^{m2} \pmod{n^2} \f$
 *  </ol>
 *
 *  @param   N                Public key
 *  @param   CT1              Ciphertext one
 *  @param   PT               Plaintext constant
 *  @param   CT               Ciphertext
 *  @return                   Returns 0 or else error code
 */
int PAILLIER_MULT(octet* N, octet* CT1, octet* PT, octet* CT);
