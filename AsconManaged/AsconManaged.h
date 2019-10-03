#pragma once

// Acknowledgement of original coders for Optimized 64bit C - Christoph Dobraunig and Martin Schläffer
// Updated and ported to C++/CLI - Dustin J. Sparks
// NOTE: BYTE ARRAY/INTEGER CONVERSIONS ARE BIG ENDIAN

#ifndef ASCON_MANAGED_H
#define ASCON_MANAGED_H

using namespace System;
using namespace System::Runtime::InteropServices;

namespace AsconManaged {
	private ref class ASCON_Core
	{
	internal:
		ref struct state { // modified from the Optimized x64 C for C++/CLI compatibility
		public:
			UInt64 x0, x1, x2, x3, x4;
			state(UInt64 X0, UInt64 X1, UInt64 X2, UInt64 X3, UInt64 X4)
			{
				x0 = X0; x1 = X1; x2 = X2; x3 = X3; x4 = X4;
			}
			state(state^ s)
			{
				x0 = s->x0; x1 = s->x1; x2 = s->x2; x3 = s->x3; x4 = s->x4;
			}
		};

		static void P12(state^% s);
		static void P8(state^% s);
		static void P6(state^% s);

		// macro for big endian machines
		//#define SWAP(x) x

		// function for little endian machines
		static UInt64 __inline SWAP(UInt64 x)
		{
			// swap adjacent 32-bit blocks
			x = (x >> 32) | (x << 32);
			// swap adjacent 16-bit blocks
			x = ((x & 0xFFFF0000FFFF0000) >> 16) | ((x & 0x0000FFFF0000FFFF) << 16);
			// swap adjacent 8-bit blocks
			return ((x & 0xFF00FF00FF00FF00) >> 8) | ((x & 0x00FF00FF00FF00FF) << 8);
		}
		static UInt32 __inline SWAP(UInt32 x)
		{
			// swap adjacent 16-bit blocks
			x = ((x & 0xFFFF0000) >> 16) | ((x & 0x0000FFFF) << 16);
			// swap adjacent 8-bit blocks
			return ((x & 0xFF00FF00) >> 8) | ((x & 0x00FF00FF) << 8);
		}
		static void _wipe(array<Byte>^ d)
		{
			if (d == nullptr || d->Length == 0) return;
			d[0] = 0xFF;
			for (Int32 i = 1; i < d->Length; i++)
			{
				d[i] = (d[0] | d[i]) ^ 0xFF;
			}
			d[0] = 0;
		}
	};

	public ref class ASCON_80pq
	{
	internal:
		static void encrypt80pq_detached(
			array<const Byte>^ Nonce, array<const Byte>^ Key,
			array<const Byte>^ AdditionalData, array<const Byte>^ Data,
			interior_ptr<Byte> output, interior_ptr<Byte> tag);
		static bool decrypt80pq_detached(
			array<const Byte>^ Nonce, array<const Byte>^ Key,
			array<const Byte>^ AdditionalData, array<const Byte>^ Data, array<const Byte>^ Tag,
			interior_ptr<Byte> output);
	public:
		static array<Byte>^ Encrypt(array<const Byte>^ Nonce, array<const Byte>^ Key, array<const Byte>^ AdditionalData, array<const Byte>^ Data)
		{
			int outLen = Data != nullptr ? Data->Length + 16 : 16;
			array<Byte>^ result = gcnew array<Byte>(outLen);
			ASCON_80pq::encrypt80pq_detached(Nonce, Key, AdditionalData, Data, &(result[0]), &(result[outLen - 16]));
			return result;
		}

		static array<Byte>^ DecryptVerify(array<const Byte>^ Nonce, array<const Byte>^ Key, array<const Byte>^ AdditionalData, array<const Byte>^ Data)
		{
			int outLen = Data != nullptr && Data->Length >= 16 ?
				Data->Length - 16 :
				throw gcnew ArgumentNullException("Data cannot be null and must be at least 16 bytes");
			array<Byte>^ result = gcnew array<Byte>(outLen);
			interior_ptr<Byte> r_ip = (outLen > 0) ?
				&(result[0]) :
				nullptr;
			array<Byte>^ tag = gcnew array<Byte>(16);
			Buffer::BlockCopy(Data, Data->Length - 16, tag, 0, 16);
			bool success = ASCON_80pq::decrypt80pq_detached(Nonce, Key, AdditionalData, Data, (array<const Byte>^)tag, r_ip);
			if (success)
				return result;
			else
			{
#ifdef _DEBUG
				System::Diagnostics::Debug::Print("*FAILED TO VERIFY CIPHERTEXT!!");
				return result; // LEAKS PLAINTEXT!!!!!! DO NOT USE IN PRODUCTION
#else
				ASCON_Core::_wipe(result);
				return nullptr;
#endif // DEBUG
			}
		}

	};

	public ref class ASCON_128
	{
	internal:
		static void encrypt128_detached(
			array<const Byte>^ Nonce, array<const Byte>^ Key,
			array<const Byte>^ AdditionalData, array<const Byte>^ Data,
			interior_ptr<Byte> output, interior_ptr<Byte> tag);
		static bool decrypt128_detached(
			array<const Byte>^ Nonce, array<const Byte>^ Key,
			array<const Byte>^ AdditionalData, array<const Byte>^ Data, array<const Byte>^ Tag,
			interior_ptr<Byte> output);
	public:
		static array<Byte>^ Encrypt(array<const Byte>^ Nonce, array<const Byte>^ Key, array<const Byte>^ AdditionalData, array<const Byte>^ Data)
		{
			int outLen = Data != nullptr ? Data->Length + 16 : 16;
			array<Byte>^ result = gcnew array<Byte>(outLen);
			ASCON_128::encrypt128_detached(Nonce, Key, AdditionalData, Data, &(result[0]), &(result[outLen - 16]));
			return result;
		}

		static array<Byte>^ DecryptVerify(array<const Byte>^ Nonce, array<const Byte>^ Key, array<const Byte>^ AdditionalData, array<const Byte>^ Data)
		{
			int outLen = Data != nullptr && Data->Length >= 16 ?
				Data->Length - 16 :
				throw gcnew ArgumentNullException("Data cannot be null and must be at least 16 bytes");
			array<Byte>^ result = gcnew array<Byte>(outLen);
			interior_ptr<Byte> r_ip = (outLen > 0) ?
				&(result[0]) :
				nullptr;
			array<Byte>^ tag = gcnew array<Byte>(16);
			Buffer::BlockCopy(Data, Data->Length - 16, tag, 0, 16);
			bool success = ASCON_128::decrypt128_detached(Nonce, Key, AdditionalData, Data, (array<const Byte>^)tag, r_ip);
			if (success)
				return result;
			else
			{
#ifdef _DEBUG
				System::Diagnostics::Debug::Print("*FAILED TO VERIFY CIPHERTEXT!!");
				return result; // LEAKS PLAINTEXT!!!!!! DO NOT USE IN PRODUCTION
#else
				ASCON_Core::_wipe(result);
				return nullptr;
#endif // DEBUG
			}
		}

	};

	public ref class ASCON_128a
	{
	internal:
		static void encrypt128a_detached(
			array<const Byte>^ Nonce, array<const Byte>^ Key,
			array<const Byte>^ AdditionalData, array<const Byte>^ Data,
			interior_ptr<Byte> output, interior_ptr<Byte> tag);
		static bool decrypt128a_detached(
			array<const Byte>^ Nonce, array<const Byte>^ Key,
			array<const Byte>^ AdditionalData, array<const Byte>^ Data, array<const Byte>^ Tag,
			interior_ptr<Byte> output);
	public:
		static array<Byte>^ Encrypt(array<const Byte>^ Nonce, array<const Byte>^ Key, array<const Byte>^ AdditionalData, array<const Byte>^ Data)
		{
			int outLen = Data != nullptr ? Data->Length + 16 : 16;
			array<Byte>^ result = gcnew array<Byte>(outLen);
			ASCON_128a::encrypt128a_detached(Nonce, Key, AdditionalData, Data, &(result[0]), &(result[outLen - 16]));
			return result;
		}

		static array<Byte>^ DecryptVerify(array<const Byte>^ Nonce, array<const Byte>^ Key, array<const Byte>^ AdditionalData, array<const Byte>^ Data)
		{
			int outLen = Data != nullptr && Data->Length >= 16 ? 
				Data->Length - 16 : 
				throw gcnew ArgumentNullException("Data cannot be null and must be at least 16 bytes");
			array<Byte>^ result = gcnew array<Byte>(outLen);
			interior_ptr<Byte> r_ip = (outLen > 0) ?
				&(result[0]) :
				nullptr;
			array<Byte>^ tag = gcnew array<Byte>(16);
			Buffer::BlockCopy(Data, Data->Length - 16, tag, 0, 16);
			bool success = ASCON_128a::decrypt128a_detached(Nonce, Key, AdditionalData, Data, (array<const Byte>^)tag, r_ip);
			if (success)
				return result;
			else
			{
#ifdef _DEBUG
				System::Diagnostics::Debug::Print("*FAILED TO VERIFY CIPHERTEXT!!");
				return result; // LEAKS PLAINTEXT!!!!!! DO NOT USE IN PRODUCTION
#else
				ASCON_Core::_wipe(result);
				return nullptr;
#endif // DEBUG
			}
		}
	};

	public ref class ASCON_Hash
	{
	internal:
		static void hash(array<const Byte>^ Data, interior_ptr<Byte> output, bool isXOF);
	public:
		static array<Byte>^ ComputeHash(array<const Byte>^ Data)
		{
			array<Byte>^ result = gcnew array<Byte>(32);
			interior_ptr<Byte> r_ip = &(result[0]);
			ASCON_Hash::hash(Data, r_ip, false);
			return result;
		}
	};

	public ref class ASCON_Xof
	{
	internal:
	public:
		static array<Byte>^ ComputeHash(array<const Byte>^ Data)
		{
			array<Byte>^ result = gcnew array<Byte>(32);
			interior_ptr<Byte> r_ip = &(result[0]);
			ASCON_Hash::hash(Data, r_ip, true);
			return result;
		}
	};
}
#endif // !ASCON_MANAGED_H