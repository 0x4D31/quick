// Copyright (c) 2019, Adel "0x4d31" Karimi.
// All rights reserved.
// Licensed under the BSD 3-Clause license.
// For full license text, see the LICENSE file in the repo root
// or https://opensource.org/licenses/BSD-3-Clause

package quick

import (
	"errors"
)

var (
	ErrWrongType = errors.New("not a QUIC ClientHello message")
	ErrBadPFlags = errors.New("QUIC packet has 0x00 public flags")
	ErrBadLength = errors.New("QUIC packet has a malformed length")
	ErrBadFtDLen = errors.New("QUIC packet has a malformed data length in Frame Type")
)

type QUICMessage struct {
	Raw            []byte
	PublicFlags    byte
	PfVersion       bool
	PfReset         bool
	PfDivNonce      bool
	PfCIDLen        bool
	PfPacketNumLen  uint8
	PfMultipath     bool
	PfReserved      bool
	CID             []byte
	Version         string
	PacketNumber    uint
}