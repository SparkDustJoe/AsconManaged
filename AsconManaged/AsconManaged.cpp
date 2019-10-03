#pragma once

// Acknowledgement of original coders for Optimized 64bit C - Christoph Dobraunig and Martin Schläffer
// Updated and ported to C++/CLI - Dustin J. Sparks
// NOTE: BYTE ARRAY/INTEGER CONVERSIONS ARE BIG ENDIAN

#ifndef ASCON_MANAGED_CPP
#define ASCON_MANAGED_CPP

#include "AsconManaged.h"
//#include <stdlib.h>
using namespace System;
using AsconManaged::ASCON_Core;
namespace AsconManaged
{


#define EXT_BYTE64(x, n) ((Byte)((UInt64)(x) >> (8 * (7 - (n)))))
#define INS_BYTE64(x, n) ((UInt64)(x) << (8 * (7 - (n))))
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

#define ROUND(C)                    \
  do {                              \
    s->x2 ^= C;                      \
    s->x0 ^= s->x4;                   \
    s->x4 ^= s->x3;                   \
    s->x2 ^= s->x1;                   \
    state^ t = gcnew state(s);        \
    s->x0 = t->x0 ^ ((~t->x1) & t->x2); \
    s->x2 = t->x2 ^ ((~t->x3) & t->x4); \
    s->x4 = t->x4 ^ ((~t->x0) & t->x1); \
    s->x1 = t->x1 ^ ((~t->x2) & t->x3); \
    s->x3 = t->x3 ^ ((~t->x4) & t->x0); \
    s->x1 ^= s->x0;                   \
    t->x1 = s->x1;                    \
    s->x1 = ROTR64(s->x1, 39);        \
    s->x3 ^= s->x2;                   \
    t->x2 = s->x2;                    \
    s->x2 = ROTR64(s->x2, 1);         \
    t->x4 = s->x4;                    \
    t->x2 ^= s->x2;                   \
    s->x2 = ROTR64(s->x2, 6 - 1);     \
    t->x3 = s->x3;                    \
    t->x1 ^= s->x1;                   \
    s->x3 = ROTR64(s->x3, 10);        \
    s->x0 ^= s->x4;                   \
    s->x4 = ROTR64(s->x4, 7);         \
    t->x3 ^= s->x3;                   \
    s->x2 ^= t->x2;                   \
    s->x1 = ROTR64(s->x1, 61 - 39);   \
    t->x0 = s->x0;                    \
    s->x2 = ~s->x2;                   \
    s->x3 = ROTR64(s->x3, 17 - 10);   \
    t->x4 ^= s->x4;                   \
    s->x4 = ROTR64(s->x4, 41 - 7);    \
    s->x3 ^= t->x3;                   \
    s->x1 ^= t->x1;                   \
    s->x0 = ROTR64(s->x0, 19);        \
    s->x4 ^= t->x4;                   \
    t->x0 ^= s->x0;                   \
    s->x0 = ROTR64(s->x0, 28 - 19);   \
    s->x0 ^= t->x0;                   \
  } while (0)

	void ASCON_Core::P12(state^% s)
	{
		ROUND(0xf0); ROUND(0xe1); ROUND(0xd2); ROUND(0xc3); 
		ROUND(0xb4); ROUND(0xa5); ROUND(0x96); ROUND(0x87); 
		ROUND(0x78); ROUND(0x69); ROUND(0x5a); ROUND(0x4b);
	} 

	void ASCON_Core::P8(state^% s)
	{
		ROUND(0xb4); ROUND(0xa5); ROUND(0x96); ROUND(0x87);
		ROUND(0x78); ROUND(0x69); ROUND(0x5a); ROUND(0x4b);
	}

	void ASCON_Core::P6(state^% s)
	{          
		ROUND(0x96); ROUND(0x87); ROUND(0x78); 
		ROUND(0x69); ROUND(0x5a); ROUND(0x4b); 
	}

// the IV is a 32-bit number (expanded to 64-bit) representing:
//   (for example on 128a) 128 bits for the Key, 128 bits for the Rate, 12 A rounds, and 8 B rounds per the original calculation
// and is constant for each Ascon version
#define IV_80pq ((UInt64)0xA0400c06 << 32)
#define IV_128 ((UInt64)0x80400c06 << 32)
#define IV_128a ((UInt64)0x80800c08 << 32)
#define IV_128hash ((UInt64)0x80800c08 << 32)
#define IV_128xof ((UInt64)0x80800c08 << 32)

	// 80pq AEAD==============================================================================================================================
	void ASCON_80pq::encrypt80pq_detached(
		array<const Byte>^ Nonce,
		array<const Byte>^ Key,
		array<const Byte>^ AdditionalData,
		array<const Byte>^ Data,
		interior_ptr<Byte> output,
		interior_ptr<Byte> tag)
	{
		if (Key == nullptr || Key->Length != 20)
			throw gcnew ArgumentException("Key must be 20 bytes in length.");
		if (Nonce == nullptr || Nonce->Length != 16)
			throw gcnew ArgumentException("Nonce must be 16 bytes in length.");
		const unsigned int RATE = 8;
		pin_ptr<const UInt32> k_pp = &(reinterpret_cast<array<UInt32>^>(Key)[0]);
		pin_ptr<const UInt64> n_pp = &(reinterpret_cast<array<UInt64>^>(Nonce)[0]);

		const UInt64 K0 = ASCON_Core::SWAP(*k_pp);
		const UInt64 K1 = ((UInt64)ASCON_Core::SWAP(*(k_pp + 1)) << 32) + ASCON_Core::SWAP(*(k_pp + 2));
		const UInt64 K2 = ((UInt64)ASCON_Core::SWAP(*(k_pp + 3)) << 32) + ASCON_Core::SWAP(*(k_pp + 4));
		const UInt64 N0 = ASCON_Core::SWAP(*n_pp);
		const UInt64 N1 = ASCON_Core::SWAP(*(n_pp + 1));
		ASCON_Core::state^ s = gcnew ASCON_Core::state(IV_80pq | K0, K1, K2, N0, N1);
		UInt64 i;

		// initialization
		ASCON_Core::P12(s);
		s->x2 ^= K0;
		s->x3 ^= K1;
		s->x4 ^= K2;

		// process associated data
		if (AdditionalData != nullptr && AdditionalData->Length > 0) {
			array<UInt64>^ a_ip = reinterpret_cast<array<UInt64>^>(AdditionalData);
			UInt32 adlen = AdditionalData->Length;
			Int32 cursor = 0;
			while (adlen >= RATE) {
				s->x0 ^= ASCON_Core::SWAP(a_ip[cursor]);
				cursor++;
				ASCON_Core::P6(s);
				adlen -= RATE;
			}
			// xor remaining bytes with state[0] or state[1] (big endian)
			UInt32 base = cursor * 8;
			for (i = 0; i < adlen; i++, base++)
				s->x0 ^= INS_BYTE64(AdditionalData[base], i);
			// append single bit '1' to end of state (big endian)
			s->x0 ^= INS_BYTE64(0x80, adlen);
			ASCON_Core::P6(s);
		}
		s->x4 ^= 1;
		// process plaintext
		UInt32 datalen = Data != nullptr ? Data->Length : 0;
		if (datalen > 0LL)
		{
			Int32 cursor = 0;
			array<UInt64>^ d_ip = reinterpret_cast<array<UInt64>^>(Data);
			//array<UInt64>^ ct_ip = reinterpret_cast<array<UInt64>^>(output);
			interior_ptr<UInt64> ct_ip = reinterpret_cast<interior_ptr<UInt64>>(output);
			while (datalen >= RATE) {
				s->x0 ^= ASCON_Core::SWAP(d_ip[cursor]);
				*(ct_ip + cursor++) = ASCON_Core::SWAP(s->x0);
				ASCON_Core::P6(s);
				datalen -= RATE;
			}
			// xor remaining bytes with state[0] or state[1] (big endian)
			UInt32 base = cursor * 8;
			interior_ptr<Byte> ct_bp = output + (cursor * 8);
			for (i = 0; i < datalen; i++, base++, ct_bp++) {
				s->x0 ^= INS_BYTE64(Data[base], i);
				*(ct_bp) = EXT_BYTE64(s->x0, i);
			}
		}
		// append single bit '1' to end of state (big endian)
		s->x0 ^= INS_BYTE64(0x80, datalen);

		// finalization
		s->x1 ^= (K0 << 32) | (K1 >> 32);
		s->x2 ^= (K1 << 32) | (K2 >> 32);
		s->x3 ^= K2 << 32;
		ASCON_Core::P12(s);
		s->x3 ^= K1;
		s->x4 ^= K2;

		// set tag
		interior_ptr<UInt64> t_ip = reinterpret_cast<interior_ptr<UInt64>>(tag);
		t_ip[0] = ASCON_Core::SWAP(s->x3);
		t_ip[1] = ASCON_Core::SWAP(s->x4);
	}

	bool ASCON_80pq::decrypt80pq_detached(
		array<const Byte>^ Nonce,
		array<const Byte>^ Key,
		array<const Byte>^ AdditionalData,
		array<const Byte>^ Data,
		array<const Byte>^ Tag,
		interior_ptr<Byte> output)
	{
		if (Key == nullptr || Key->Length != 20)
			throw gcnew ArgumentException("Key must be 20 bytes in length.");
		if (Nonce == nullptr || Nonce->Length != 16)
			throw gcnew ArgumentException("Nonce must be 16 bytes in length.");
		const unsigned int RATE = 8;

		pin_ptr<const UInt32> k_pp = &(reinterpret_cast<array<UInt32>^>(Key)[0]);
		pin_ptr<const UInt64> n_pp = &(reinterpret_cast<array<UInt64>^>(Nonce)[0]);

		const UInt64 K0 = ASCON_Core::SWAP(*k_pp);
		const UInt64 K1 = ((UInt64)ASCON_Core::SWAP(*(k_pp + 1)) << 32) + ASCON_Core::SWAP(*(k_pp + 2));
		const UInt64 K2 = ((UInt64)ASCON_Core::SWAP(*(k_pp + 3)) << 32) + ASCON_Core::SWAP(*(k_pp + 4)); 
		const UInt64 N0 = ASCON_Core::SWAP(*n_pp);
		const UInt64 N1 = ASCON_Core::SWAP(*(n_pp + 1));
		ASCON_Core::state^ s = gcnew ASCON_Core::state(IV_80pq | K0, K1, K2, N0, N1);
		UInt64 i;

		// initialization
		ASCON_Core::P12(s);
		s->x2 ^= K0;
		s->x3 ^= K1;
		s->x4 ^= K2;

		UInt32 adlen = 0;
		// process associated data
		if (AdditionalData != nullptr && AdditionalData->Length > 0) {
			array<UInt64>^ a_ip = reinterpret_cast<array<UInt64>^>(AdditionalData);
			adlen = AdditionalData->Length;
#ifdef _DEBUG
			System::Diagnostics::Debug::Print("ADLEN=" + adlen.ToString());
#endif // _DEBUG
			Int32 cursor = 0;
			while (adlen >= RATE) {
				s->x0 ^= ASCON_Core::SWAP(a_ip[cursor]);
				cursor++;
				ASCON_Core::P6(s);
				adlen -= RATE;
			}
			// xor remaining bytes with state[0] or state[1] (big endian)
			UInt32 base = cursor * 8;
			for (i = 0; i < adlen; i++, base++)
				s->x0 ^= INS_BYTE64(AdditionalData[base], i);
			// append single bit '1' to end of state (big endian)
			s->x0 ^= INS_BYTE64(0x80, adlen);
			ASCON_Core::P6(s);
		}
		s->x4 ^= 1;
		// process ciphertext
		UInt32 dataLen = Data != nullptr ? Data->Length - 16 : 0;
#ifdef _DEBUG
		System::Diagnostics::Debug::Print("PTLEN=" + dataLen.ToString());
#endif // _DEBUG
		if (dataLen > 0LL)
		{
			Int32 cursor = 0;
			array<UInt64>^ d_ip = reinterpret_cast<array<UInt64>^>(Data);
			//array<UInt64>^ ct_ip = reinterpret_cast<array<UInt64>^>(output);
			interior_ptr<UInt64> pt_ip = reinterpret_cast<interior_ptr<UInt64>>(output);
			while (dataLen >= RATE) {
				*(pt_ip + cursor) = ASCON_Core::SWAP(s->x0) ^ d_ip[cursor];
				s->x0 = ASCON_Core::SWAP(d_ip[cursor]);
				cursor++;
				ASCON_Core::P6(s);
				dataLen -= RATE;
			}
			// xor remaining bytes with state[0] or state[1] (big endian)
			UInt32 base = cursor * 8;
			interior_ptr<Byte> pt_bp = output + (cursor * 8);
			for (i = 0; i < dataLen; i++, base++, pt_bp++) {
				*(pt_bp) = Data[base] ^ EXT_BYTE64(s->x0, i);
				s->x0 &= ~(INS_BYTE64(0xff, i)); // mask byte position
				s->x0 |= INS_BYTE64(Data[base], i); // apply ct byte
			}
		}
		// append single bit '1' to end of state (big endian)
		s->x0 ^= INS_BYTE64(0x80, dataLen);

		// finalization
		s->x1 ^= (K0 << 32) | (K1 >> 32);
		s->x2 ^= (K1 << 32) | (K2 >> 32);
		s->x3 ^= K2 << 32;
		ASCON_Core::P12(s);
		s->x3 ^= K1;
		s->x4 ^= K2;

		// verify tag
		array<Byte>^ tempTag = gcnew array<Byte>(16);
		interior_ptr<UInt64> t_ip = &(reinterpret_cast<array<UInt64>^>(tempTag)[0]);
		t_ip[0] = ASCON_Core::SWAP(s->x3);
		t_ip[1] = ASCON_Core::SWAP(s->x4);
		UInt16 result = 0;
		for (i = 0; i < 16; i++) result |= tempTag[(Byte)i] ^ Tag[(Byte)i];
#ifdef _DEBUG
		if (result != 0)
		{
			System::Diagnostics::Debug::Print("TAG MISMATCH!");
			for (i = 0; i < 16; i++)
			{
				System::Diagnostics::Debug::Print("EXPECTED " + Tag[(Byte)i].ToString("x2") + " GOT " + tempTag[(Byte)i].ToString("x2"));
			}
		}
#endif // _DEBUG
		return result == 0;
	}

	// 128 AEAD==============================================================================================================================
	void ASCON_128::encrypt128_detached(
		array<const Byte>^ Nonce,
		array<const Byte>^ Key,
		array<const Byte>^ AdditionalData,
		array<const Byte>^ Data,
		interior_ptr<Byte> output,
		interior_ptr<Byte> tag)
	{
		if (Key == nullptr || Key->Length != 16)
			throw gcnew ArgumentException("Key must be 16 bytes in length.");
		if (Nonce == nullptr || Nonce->Length != 16)
			throw gcnew ArgumentException("Nonce must be 16 bytes in length.");
		const unsigned int RATE = 8;
		pin_ptr<const UInt64> k_pp = &(reinterpret_cast<array<UInt64>^>(Key)[0]);
		pin_ptr<const UInt64> n_pp = &(reinterpret_cast<array<UInt64>^>(Nonce)[0]);

		const UInt64 K0 = ASCON_Core::SWAP(*k_pp);
		const UInt64 K1 = ASCON_Core::SWAP(*(k_pp + 1));
		const UInt64 N0 = ASCON_Core::SWAP(*n_pp);
		const UInt64 N1 = ASCON_Core::SWAP(*(n_pp + 1));
		ASCON_Core::state^ s = gcnew ASCON_Core::state(IV_128, K0, K1, N0, N1);
		UInt64 i;

		// initialization
		ASCON_Core::P12(s);
		s->x3 ^= K0;
		s->x4 ^= K1;

		// process associated data
		if (AdditionalData != nullptr && AdditionalData->Length > 0) {
			array<UInt64>^ a_ip = reinterpret_cast<array<UInt64>^>(AdditionalData);
			UInt32 adlen = AdditionalData->Length;
			Int32 cursor = 0;
			while (adlen >= RATE) {
				s->x0 ^= ASCON_Core::SWAP(a_ip[cursor]);
				cursor++;
				ASCON_Core::P6(s);
				adlen -= RATE;
			}
			// xor remaining bytes with state[0] or state[1] (big endian)
			UInt32 base = cursor * 8;
			for (i = 0; i < adlen; i++, base++)
				s->x0 ^= INS_BYTE64(AdditionalData[base], i);
			// append single bit '1' to end of state (big endian)
			s->x0 ^= INS_BYTE64(0x80, adlen);
			ASCON_Core::P6(s);
		}
		s->x4 ^= 1;
		// process plaintext
		UInt32 datalen = Data != nullptr ? Data->Length : 0;
		if (datalen > 0LL)
		{
			Int32 cursor = 0;
			array<UInt64>^ d_ip = reinterpret_cast<array<UInt64>^>(Data);
			//array<UInt64>^ ct_ip = reinterpret_cast<array<UInt64>^>(output);
			interior_ptr<UInt64> ct_ip = reinterpret_cast<interior_ptr<UInt64>>(output);
			while (datalen >= RATE) {
				s->x0 ^= ASCON_Core::SWAP(d_ip[cursor]);
				*(ct_ip + cursor++) = ASCON_Core::SWAP(s->x0);
				ASCON_Core::P6(s);
				datalen -= RATE;
			}
			// xor remaining bytes with state[0] or state[1] (big endian)
			UInt32 base = cursor * 8;
			interior_ptr<Byte> ct_bp = output + (cursor * 8);
			for (i = 0; i < datalen; i++, base++, ct_bp++) {
				s->x0 ^= INS_BYTE64(Data[base], i);
				*(ct_bp) = EXT_BYTE64(s->x0, i);
			}
		}
		// append single bit '1' to end of state (big endian)
		s->x0 ^= INS_BYTE64(0x80, datalen);

		// finalization
		s->x1 ^= K0;
		s->x2 ^= K1;
		ASCON_Core::P12(s);
		s->x3 ^= K0;
		s->x4 ^= K1;

		// set tag
		interior_ptr<UInt64> t_ip = reinterpret_cast<interior_ptr<UInt64>>(tag);
		t_ip[0] = ASCON_Core::SWAP(s->x3);
		t_ip[1] = ASCON_Core::SWAP(s->x4);
	}

	bool ASCON_128::decrypt128_detached(
		array<const Byte>^ Nonce,
		array<const Byte>^ Key,
		array<const Byte>^ AdditionalData,
		array<const Byte>^ Data,
		array<const Byte>^ Tag,
		interior_ptr<Byte> output)
	{
		if (Key == nullptr || Key->Length != 16)
			throw gcnew ArgumentException("Key must be 16 bytes in length.");
		if (Nonce == nullptr || Nonce->Length != 16)
			throw gcnew ArgumentException("Nonce must be 16 bytes in length.");
		const unsigned int RATE = 8;

		pin_ptr<const UInt64> k_pp = &(reinterpret_cast<array<UInt64>^>(Key)[0]);
		pin_ptr<const UInt64> n_pp = &(reinterpret_cast<array<UInt64>^>(Nonce)[0]);

		const UInt64 K0 = ASCON_Core::SWAP(*k_pp);
		const UInt64 K1 = ASCON_Core::SWAP(*(k_pp + 1));
		const UInt64 N0 = ASCON_Core::SWAP(*n_pp);
		const UInt64 N1 = ASCON_Core::SWAP(*(n_pp + 1));
		ASCON_Core::state^ s = gcnew ASCON_Core::state(IV_128, K0, K1, N0, N1);
		UInt64 i;

		// initialization
		ASCON_Core::P12(s);
		s->x3 ^= K0;
		s->x4 ^= K1;
		UInt32 adlen = 0;
		// process associated data
		if (AdditionalData != nullptr && AdditionalData->Length > 0) {
			array<UInt64>^ a_ip = reinterpret_cast<array<UInt64>^>(AdditionalData);
			adlen = AdditionalData->Length;
#ifdef _DEBUG
			System::Diagnostics::Debug::Print("ADLEN=" + adlen.ToString());
#endif // _DEBUG
			Int32 cursor = 0;
			while (adlen >= RATE) {
				s->x0 ^= ASCON_Core::SWAP(a_ip[cursor]);
				cursor++;
				ASCON_Core::P6(s);
				adlen -= RATE;
			}
			// xor remaining bytes with state[0] or state[1] (big endian)
			UInt32 base = cursor * 8;
			for (i = 0; i < adlen; i++, base++)
				s->x0 ^= INS_BYTE64(AdditionalData[base], i);
			// append single bit '1' to end of state (big endian)
			s->x0 ^= INS_BYTE64(0x80, adlen);
			ASCON_Core::P6(s);
		}
		s->x4 ^= 1;
		// process ciphertext
		UInt32 dataLen = Data != nullptr ? Data->Length - 16 : 0;
#ifdef _DEBUG
		System::Diagnostics::Debug::Print("PTLEN=" + dataLen.ToString());
#endif // _DEBUG
		if (dataLen > 0LL)
		{
			Int32 cursor = 0;
			array<UInt64>^ d_ip = reinterpret_cast<array<UInt64>^>(Data);
			//array<UInt64>^ ct_ip = reinterpret_cast<array<UInt64>^>(output);
			interior_ptr<UInt64> pt_ip = reinterpret_cast<interior_ptr<UInt64>>(output);
			while (dataLen >= RATE) {
				*(pt_ip + cursor) = ASCON_Core::SWAP(s->x0) ^ d_ip[cursor];
				s->x0 = ASCON_Core::SWAP(d_ip[cursor]);
				cursor++;
				ASCON_Core::P6(s);
				dataLen -= RATE;
			}
			// xor remaining bytes with state[0] or state[1] (big endian)
			UInt32 base = cursor * 8;
			interior_ptr<Byte> pt_bp = output + (cursor * 8);
			for (i = 0; i < dataLen; i++, base++, pt_bp++) {
				*(pt_bp) = Data[base] ^ EXT_BYTE64(s->x0, i);
				s->x0 &= ~(INS_BYTE64(0xff, i)); // mask byte position
				s->x0 |= INS_BYTE64(Data[base], i); // apply ct byte
			}
		}
		// append single bit '1' to end of state (big endian)
		s->x0 ^= INS_BYTE64(0x80, dataLen);

		// finalization
		s->x1 ^= K0;
		s->x2 ^= K1;
		ASCON_Core::P12(s);
		s->x3 ^= K0;
		s->x4 ^= K1;

		// verify tag
		array<Byte>^ tempTag = gcnew array<Byte>(16);
		interior_ptr<UInt64> t_ip = &(reinterpret_cast<array<UInt64>^>(tempTag)[0]);
		t_ip[0] = ASCON_Core::SWAP(s->x3);
		t_ip[1] = ASCON_Core::SWAP(s->x4);
		UInt16 result = 0;
		for (i = 0; i < 16; i++) result |= tempTag[(Byte)i] ^ Tag[(Byte)i];
#ifdef _DEBUG
		if (result != 0)
		{
			System::Diagnostics::Debug::Print("TAG MISMATCH!");
			for (i = 0; i < 16; i++)
			{
				System::Diagnostics::Debug::Print("EXPECTED " + Tag[(Byte)i].ToString("x2") + " GOT " + tempTag[(Byte)i].ToString("x2"));
			}
		}
#endif // _DEBUG
		return result == 0;
	}

	// 128a AEAD==============================================================================================================================
	void ASCON_128a::encrypt128a_detached(
		array<const Byte>^ Nonce, 
		array<const Byte>^ Key, 
		array<const Byte>^ AdditionalData, 
		array<const Byte>^ Data,
		interior_ptr<Byte> output,
		interior_ptr<Byte> tag)
	{
		if (Key == nullptr || Key->Length != 16)
			throw gcnew ArgumentException("Key must be 16 bytes in length.");
		if (Nonce == nullptr || Nonce->Length != 16)
			throw gcnew ArgumentException("Nonce must be 16 bytes in length.");
		const unsigned int RATE = 16;
		pin_ptr<const UInt64> k_pp = &(reinterpret_cast<array<UInt64>^>(Key)[0]);
		pin_ptr<const UInt64> n_pp = &(reinterpret_cast<array<UInt64>^>(Nonce)[0]);
		
		const UInt64 K0 = ASCON_Core::SWAP(*k_pp);
		const UInt64 K1 = ASCON_Core::SWAP(*(k_pp + 1));
		const UInt64 N0 = ASCON_Core::SWAP(*n_pp);
		const UInt64 N1 = ASCON_Core::SWAP(*(n_pp +1));
		ASCON_Core::state^ s = gcnew ASCON_Core::state(IV_128a, K0, K1, N0, N1);
		UInt64 i;

		// initialization
		ASCON_Core::P12(s);
		s->x3 ^= K0;
		s->x4 ^= K1;

		// process associated data
		if (AdditionalData != nullptr && AdditionalData->Length > 0) {
			array<UInt64>^ a_ip = reinterpret_cast<array<UInt64>^>(AdditionalData);
			UInt32 adlen = AdditionalData->Length;
			Int32 cursor = 0;
			while (adlen >= RATE) {
				s->x0 ^= ASCON_Core::SWAP(a_ip[cursor]);
				cursor++;
				s->x1 ^= ASCON_Core::SWAP(a_ip[cursor]);
				cursor++;
				ASCON_Core::P8(s);
				adlen -= RATE;
			}
			// xor remaining bytes with state[0] or state[1] (big endian)
			UInt32 base = cursor * 8;
			for (i = 0; i < adlen; i++, base++)
				if (i < 8)
					s->x0 ^= INS_BYTE64(AdditionalData[base], i);
				else
					s->x1 ^= INS_BYTE64(AdditionalData[base], i % 8);
			// append single bit '1' to end of state (big endian)
			if (adlen < 8)
				s->x0 ^= INS_BYTE64(0x80, adlen);
			else
				s->x1 ^= INS_BYTE64(0x80, adlen % 8);
			ASCON_Core::P8(s);
		}
		s->x4 ^= 1;
		// process plaintext
		UInt32 datalen = Data != nullptr ? Data->Length : 0;
		if (datalen > 0LL)
		{
			Int32 cursor = 0;
			array<UInt64>^ d_ip = reinterpret_cast<array<UInt64>^>(Data);
			interior_ptr<UInt64> ct_ip = reinterpret_cast<interior_ptr<UInt64>>(output);
			while (datalen >= RATE) {
				s->x0 ^= ASCON_Core::SWAP(d_ip[cursor]);
				*(ct_ip + cursor++) = ASCON_Core::SWAP(s->x0);
				s->x1 ^= ASCON_Core::SWAP(d_ip[cursor]);
				*(ct_ip + cursor++) = ASCON_Core::SWAP(s->x1);
				ASCON_Core::P8(s);
				datalen -= RATE;
			}
			// xor remaining bytes with state[0] or state[1] (big endian)
			UInt32 base = cursor * 8;
			interior_ptr<Byte> ct_bp = output + (cursor * 8);
			for (i = 0; i < datalen; i++, base++, ct_bp++) {
				if (i < 8) {
					s->x0 ^= INS_BYTE64(Data[base], i);
					*(ct_bp) = EXT_BYTE64(s->x0, i);
				}
				else {
					s->x1 ^= INS_BYTE64(Data[base], i % 8);
					*(ct_bp) = EXT_BYTE64(s->x1, i % 8);
				}
			}
		}
		// append single bit '1' to end of state (big endian)
		if (datalen < 8)
			s->x0 ^= INS_BYTE64(0x80, datalen);
		else
			s->x1 ^= INS_BYTE64(0x80, datalen - 8);
		
		// finalization
		s->x2 ^= K0;
		s->x3 ^= K1;
		ASCON_Core::P12(s);
		s->x3 ^= K0;
		s->x4 ^= K1;

		// set tag
		interior_ptr<UInt64> t_ip = reinterpret_cast<interior_ptr<UInt64>>(tag);
		t_ip[0] = ASCON_Core::SWAP(s->x3);
		t_ip[1] = ASCON_Core::SWAP(s->x4);
	}

	bool ASCON_128a::decrypt128a_detached(
		array<const Byte>^ Nonce,
		array<const Byte>^ Key,
		array<const Byte>^ AdditionalData,
		array<const Byte>^ Data,
		array<const Byte>^ Tag,
		interior_ptr<Byte> output)
	{
		if (Key == nullptr || Key->Length != 16)
			throw gcnew ArgumentException("Key must be 16 bytes in length.");
		if (Nonce == nullptr || Nonce->Length != 16)
			throw gcnew ArgumentException("Nonce must be 16 bytes in length.");
		const unsigned int RATE = 16;

		pin_ptr<const UInt64> k_pp = &(reinterpret_cast<array<UInt64>^>(Key)[0]);
		pin_ptr<const UInt64> n_pp = &(reinterpret_cast<array<UInt64>^>(Nonce)[0]);

		const UInt64 K0 = ASCON_Core::SWAP(*k_pp);
		const UInt64 K1 = ASCON_Core::SWAP(*(k_pp + 1));
		const UInt64 N0 = ASCON_Core::SWAP(*n_pp);
		const UInt64 N1 = ASCON_Core::SWAP(*(n_pp + 1));
		ASCON_Core::state^ s = gcnew ASCON_Core::state(IV_128a, K0, K1, N0, N1);
		UInt64 i;

		// initialization
		ASCON_Core::P12(s);
		s->x3 ^= K0;
		s->x4 ^= K1;
		UInt32 adlen = 0;
		// process associated data
		if (AdditionalData != nullptr && AdditionalData->Length > 0) {
			array<UInt64>^ a_ip = reinterpret_cast<array<UInt64>^>(AdditionalData);
			adlen = AdditionalData->Length;
#ifdef _DEBUG
			System::Diagnostics::Debug::Print("ADLEN=" + adlen.ToString());
#endif // _DEBUG
			Int32 cursor = 0;
			while (adlen >= RATE) {
				s->x0 ^= ASCON_Core::SWAP(a_ip[cursor]);
				cursor++;
				s->x1 ^= ASCON_Core::SWAP(a_ip[cursor]);
				cursor++;
				ASCON_Core::P8(s);
				adlen -= RATE;
			}
			// xor remaining bytes with state[0] or state[1] (big endian)
			UInt32 base = cursor * 8;
			for (i = 0; i < adlen; i++, base++)
				if (i < 8)
					s->x0 ^= INS_BYTE64(AdditionalData[base], i);
				else
					s->x1 ^= INS_BYTE64(AdditionalData[base], i % 8);
			// append single bit '1' to end of state (big endian)
			if (adlen < 8)
				s->x0 ^= INS_BYTE64(0x80, adlen);
			else
				s->x1 ^= INS_BYTE64(0x80, adlen % 8);
			ASCON_Core::P8(s);
		}
		s->x4 ^= 1;
		// process ciphertext
		UInt32 datalen = Data != nullptr ? Data->Length - 16 : 0;
#ifdef _DEBUG
		System::Diagnostics::Debug::Print("PTLEN=" + datalen.ToString());
#endif // _DEBUG
		if (datalen > 0LL)
		{
			Int32 cursor = 0;
			array<UInt64>^ d_ip = reinterpret_cast<array<UInt64>^>(Data);
			//array<UInt64>^ ct_ip = reinterpret_cast<array<UInt64>^>(output);
			interior_ptr<UInt64> pt_ip = reinterpret_cast<interior_ptr<UInt64>>(output);
			while (datalen >= RATE) {
				*(pt_ip + cursor) = ASCON_Core::SWAP(s->x0) ^ d_ip[cursor];
				s->x0 = ASCON_Core::SWAP(d_ip[cursor]);
				cursor++;
				*(pt_ip + cursor) = ASCON_Core::SWAP(s->x1) ^ d_ip[cursor];
				s->x1 = ASCON_Core::SWAP(d_ip[cursor]);
				cursor++;
				ASCON_Core::P8(s);
				datalen -= RATE;
			}
			// xor remaining bytes with state[0] or state[1] (big endian)
			UInt32 base = cursor * 8;
			interior_ptr<Byte> pt_bp = output + (cursor * 8);
			for (i = 0; i < datalen; i++, base++, pt_bp++) {
				if (i < 8) {
					*(pt_bp) = Data[base] ^ EXT_BYTE64(s->x0, i);
					s->x0 &= ~(INS_BYTE64(0xff, i)); // mask byte position
					s->x0 |= INS_BYTE64(Data[base], i); // apply ct byte
				}
				else {
					*(pt_bp) = Data[base] ^ EXT_BYTE64(s->x1, i % 8);
					s->x1 &= ~(INS_BYTE64(0xff, i % 8)); // mask byte position
					s->x1 |= INS_BYTE64(Data[base], i % 8); // apply ct byte
				}
			}
		}
		// append single bit '1' to end of state (big endian)
		if (datalen < 8)
			s->x0 ^= INS_BYTE64(0x80, datalen);
		else
			s->x1 ^= INS_BYTE64(0x80, datalen % 8);

		// finalization
		s->x2 ^= K0;
		s->x3 ^= K1;
		ASCON_Core::P12(s);
		s->x3 ^= K0;
		s->x4 ^= K1;

		// verify tag
		array<Byte>^ tempTag = gcnew array<Byte>(16);
		interior_ptr<UInt64> t_ip = &(reinterpret_cast<array<UInt64>^>(tempTag)[0]);
		t_ip[0] = ASCON_Core::SWAP(s->x3);
		t_ip[1] = ASCON_Core::SWAP(s->x4);
		UInt16 result = 0;
		for (i = 0; i < 16; i++) result |= tempTag[(Byte)i] ^ Tag[(Byte)i];
#ifdef _DEBUG
		if (result != 0)
		{
			System::Diagnostics::Debug::Print("TAG MISMATCH!");
			for (i = 0; i < 16; i++)
			{
				System::Diagnostics::Debug::Print("EXPECTED " + Tag[(Byte)i].ToString("x2") + " GOT " + tempTag[(Byte)i].ToString("x2"));
			}
		}
#endif // _DEBUG
		return result == 0;
	}

	//hash====================================================================================================================
	void ASCON_Hash::hash(array<const Byte>^ Data, interior_ptr<Byte> output, bool isXOF) {
		// initialization
		ASCON_Core::state^ s;
		
		if (isXOF)
			s= gcnew ASCON_Core::state(
				0xb57e273b814cd416ull,
				0x2b51042562ae2420ull,
				0x66a3a7768ddf2218ull,
				0x5aad0a7a8153650cull,
				0x4f3e0e32539493b6ull);
		else
			s = gcnew ASCON_Core::state(
				0xee9398aadb67f03dull,
				0x8bb21831c60f1002ull,
				0xb48a92db98d5da62ull,
				0x43189921b8f8e3e8ull,
				0x348fa5c9d525e140ull);
		UInt64 i;
		const unsigned int RATE = 8;

		// absorb message
		UInt32 dataLen = Data != nullptr ? Data->Length : 0;
		if (dataLen > 0)
		{
			Int32 cursor = 0;
			array<UInt64>^ d = reinterpret_cast<array<UInt64>^>(Data);
			while (dataLen >= RATE) {
				s->x0 ^= ASCON_Core::SWAP(d[cursor]);
				cursor++;
				ASCON_Core::P12(s);
				dataLen -= RATE;
			}
			UInt32 base = cursor * 8;
			for (i = 0; i < dataLen; i++, base++)
				s->x0 ^= INS_BYTE64(Data[base], i);
		}
		s->x0 ^= INS_BYTE64(0x80, dataLen); // append single bit 1
		ASCON_Core::P12(s);
		interior_ptr<UInt64> o_ip = reinterpret_cast<interior_ptr<UInt64>>(output);
		// finalize & output (4 8-byte uints converted from BIG ENDIAN as necessary)
		*(o_ip++) = ASCON_Core::SWAP(s->x0);
		ASCON_Core::P12(s);
		*(o_ip++) = ASCON_Core::SWAP(s->x0);
		ASCON_Core::P12(s);
		*(o_ip++) = ASCON_Core::SWAP(s->x0);
		ASCON_Core::P12(s);
		*(o_ip++) = ASCON_Core::SWAP(s->x0);

		return;
	}

}
#endif // !ASCON_MANAGED_CPP
