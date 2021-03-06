// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_QUIC_UTILS_H_
#define NET_QUIC_CORE_QUIC_UTILS_H_

#include <cstddef>
#include <cstdint>
#include <string>

#include "base/macros.h"
#include "net/base/int128.h"
#include "net/quic/core/quic_error_codes.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/platform/api/quic_export.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/quic/platform/api/quic_string_piece.h"

// HONESTCHOI added it due to honest_conf_setup()
#include <cstdio>
#define HONEST_DBG_MSG_BUF_SIZE 300*1024*1024 // 300MB 
#define HONEST_MAX_FILE_NAME 1024

namespace net {

class QUIC_EXPORT_PRIVATE QuicUtils {
 public:
  // Returns the 64 bit FNV1a hash of the data.  See
  // http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
  static uint64_t FNV1a_64_Hash(QuicStringPiece data);

  // Returns the 128 bit FNV1a hash of the data.  See
  // http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
  static uint128 FNV1a_128_Hash(QuicStringPiece data);

  // Returns the 128 bit FNV1a hash of the two sequences of data.  See
  // http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
  static uint128 FNV1a_128_Hash_Two(QuicStringPiece data1,
                                    QuicStringPiece data2);

  // Returns the 128 bit FNV1a hash of the three sequences of data.  See
  // http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
  static uint128 FNV1a_128_Hash_Three(QuicStringPiece data1,
                                      QuicStringPiece data2,
                                      QuicStringPiece data3);

  // SerializeUint128 writes the first 96 bits of |v| in little-endian form
  // to |out|.
  static void SerializeUint128Short(uint128 v, uint8_t* out);

  // Returns the level of encryption as a char*
  static const char* EncryptionLevelToString(EncryptionLevel level);

  // Returns TransmissionType as a char*
  static const char* TransmissionTypeToString(TransmissionType type);

  // Returns PeerAddressChangeType as a std::string.
  static std::string PeerAddressChangeTypeToString(PeerAddressChangeType type);

  // Determines and returns change type of address change from |old_address| to
  // |new_address|.
  static PeerAddressChangeType DetermineAddressChangeType(
      const QuicSocketAddress& old_address,
      const QuicSocketAddress& new_address);

  // HONESTCHOI added belows                              
  static void honest_print_backtrace(const std::string func_name);

  // Set by honest_conf_setup()
  static uint32_t honest_DefaultMaxPacketSize;
  static uint32_t honest_MaxPacketSize;
  static uint32_t honest_MtuDiscoveryTargetPacketSizeHigh;
  static uint32_t honest_MtuDiscoveryTargetPacketSizeLow;
  static uint32_t honest_DefaultNumConnections;
  static float honest_PacingRate;
  static int honest_UsingPacing;
  static uint32_t honest_Granularity;
  static uint32_t honest_ExperimentSeq;
  static char honest_ProcessName[HONEST_MAX_FILE_NAME];
  static int32_t honest_UsingHonestFatal;

  static int honest_conf_setup(void);
  static void honest_sigint_handler(int s);
  // HONESTCHOI added above                              

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicUtils);
};

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_UTILS_H_
