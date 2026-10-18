using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Edge_tts_sharp;

/// <summary>
/// 生成 Edge 朗读接口的 Sec-MS-GEC v2 令牌（格式 "CS64-SHA256"）。
/// 算法移植自 edge-tts 7.x 的 drm.py。微软已不再接受旧的 v1（纯 SHA256）令牌，
/// 继续使用会导致 WebSocket 握手被拒绝（HTTP 403）。
/// </summary>
public static class SecMsGec
{
    private const string TrustedClientToken = "6A5AA1D4EAFF4E9FB37E23D68491D6F4";
    private const long WinEpochSeconds = 11644473600L;

    private static readonly uint[] Sha256Initial =
    {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };

    private static readonly uint[] Sha256State =
    {
        0xFD9FBEA2, 0x91243CE7, 0xBE499094, 0xCD2E1E0A,
        0x6C006F49, 0x04BD35AB, 0xFEB0A7E4, 0x03EFFBD2
    };

    private static readonly uint[] Sha256Schedule =
    {
        0xEB24BF9E, 0x1558691F, 0xA0C09EE2, 0x0CFA32BA, 0xA622EE8C, 0xD1DD9491, 0xC0DD25A0,
        0xF9E70AB6, 0xF0C31573, 0x7058CE4E, 0x7188E606, 0x00E5AB33, 0xD258B060, 0x72766564
    };

    private static readonly uint[] RoundConstants =
    {
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
    };

    private const uint Sha256Adjustment = 0xC9DC06A7;
    private const uint Sigma0Adjustment = 0x059C0B80;
    private const uint Sigma1Adjustment = 0x000B92C0;

    private static readonly uint[] BlockConstants = BuildBlockConstants();

    private static readonly (uint Coefficient, uint Offset)[] Cs64Coefficients =
    {
        (0xE82E91B1, 0xB32700D0), (0x44DE24C6, 0x88DFF51D), (0x3BEB65BC, 0x29514038),
        (0xC89C5933, 0xB328CBDF), (0x8D1EC211, 0xD405B4D5), (0x314EF5D5, 0x26E55F3C),
        (0xE92491B1, 0x607801C6), (0xF0A5B9D5, 0x82B2C1FB), (0x06064CF3, 0xFA51A3DA),
        (0xDA79FA60, 0x207CC464), (0xBED20560, 0x3C3C74F3), (0x89F9C9F8, 0xD2D14B61),
        (0x35FA38C6, 0xBB04A2C1), (0xCB49E3C6, 0xC5626167)
    };

    private const uint Cs64Factor = 0x82893933;
    private const uint Cs64Adjustment0 = 0xF2F90B1A;
    private const uint Cs64Adjustment1 = 0x0B1A0000;

    /// <summary>
    /// 生成当前时刻的 v2 令牌。
    /// </summary>
    public static string Generate() => Generate(DateTimeOffset.UtcNow.ToUnixTimeSeconds());

    /// <summary>
    /// 用指定 Unix 时间（秒）生成 v2 令牌，便于对照测试。
    /// </summary>
    public static string Generate(long unixSeconds)
    {
        var ticks = unixSeconds + WinEpochSeconds;
        ticks -= ticks % 300;
        var fileTime = ticks * 10_000_000L;
        var data = Encoding.ASCII.GetBytes(
            fileTime.ToString(CultureInfo.InvariantCulture) + TrustedClientToken);

        var digest = Sha256Digest(data);
        var (cs64A, cs64B) = Cs64Digest(data, digest);

        Span<byte> cs64 = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(cs64, cs64A);
        BinaryPrimitives.WriteUInt32LittleEndian(cs64[4..], cs64B);

        return Convert.ToHexString(cs64) + "-" + Convert.ToHexString(digest);
    }

    private static uint[] BuildBlockConstants()
    {
        var constants = new uint[64];
        Array.Copy(RoundConstants, constants, 64);
        constants[14] = Sha256Adjustment;
        return constants;
    }

    private static uint Rol16(uint value) => (value << 16) | (value >> 16);

    private static uint Sigma0(uint value) =>
        (value >> 7) ^ (value << 25) ^ (value >> 18) ^ (value << 14) ^ (value >> 3);

    private static uint Sigma1(uint value) =>
        (value >> 17) ^ (value << 15) ^ (value >> 19) ^ (value << 13) ^ (value >> 10);

    private static void ExpandSchedule(uint[] words, int firstWord)
    {
        for (var index = firstWord; index < 64; index++)
        {
            var x = words[index - 2];
            var y = words[index - 15];
            var sigma1 = (x >> 17) ^ (x << 15) ^ (x >> 19) ^ (x << 13) ^ (x >> 10);
            var sigma0 = (y >> 7) ^ (y << 25) ^ (y >> 18) ^ (y << 14) ^ (y >> 3);
            words[index] = unchecked(sigma1 + words[index - 7] + sigma0 + words[index - 16]);
        }
    }

    private static uint[] Sha256Init(ReadOnlySpan<byte> prefix)
    {
        var words = new uint[64];
        words[14] = (uint)((prefix[0] << 16) | (prefix[1] << 8) | prefix[2]);
        words[15] = (uint)((prefix[3] << 24) | (prefix[4] << 16) | (prefix[5] << 8) | prefix[6]);

        for (var index = 16; index < 30; index++)
        {
            var value = Sha256Schedule[index - 16];
            if (index - 2 >= 14)
                value = unchecked(value + (index == 16
                    ? Sigma1(words[index - 2]) ^ Sigma1Adjustment
                    : Sigma1(words[index - 2])));
            if (index - 7 >= 14)
                value = unchecked(value + words[index - 7]);
            if (index - 15 >= 14)
                value = unchecked(value + (index == 29
                    ? Sigma0(words[index - 15]) ^ Sigma0Adjustment
                    : Sigma0(words[index - 15])));
            words[index] = value;
        }

        words[30] = unchecked(Sigma1(words[28]) + words[23] + Sigma0(words[15]) + words[14]
                              + Sha256Adjustment - RoundConstants[14]);

        ExpandSchedule(words, 31);
        var working = Sha256Rounds(Sha256State, words, 14);

        var result = new uint[8];
        for (var i = 0; i < 8; i++)
            result[i] = unchecked(Sha256Initial[i] + working[i]);
        return result;
    }

    private static uint[] Sha256Rounds(uint[] state, uint[] words, int firstRound)
    {
        uint a = state[0], b = state[1], c = state[2], d = state[3];
        uint e = state[4], f = state[5], g = state[6], h = state[7];

        var constants = firstRound == 14 ? BlockConstants : RoundConstants;
        var aligned = Math.Min(64, (firstRound + 7) / 8 * 8);

        for (var index = firstRound; index < aligned; index++)
        {
            var rotE = (ulong)e * 0x100000001UL;
            var rotA = (ulong)a * 0x100000001UL;
            var t1 = unchecked(h
                               + (uint)((rotE >> 6) ^ (rotE >> 11) ^ (rotE >> 25))
                               + (g ^ (e & (f ^ g)))
                               + constants[index] + words[index]);
            var t2 = unchecked((uint)((rotA >> 2) ^ (rotA >> 13) ^ (rotA >> 22))
                               + ((a & b) | (c & (a | b))));
            var newA = unchecked(t1 + t2);
            var newE = unchecked(d + t1);
            (a, b, c, d, e, f, g, h) = (newA, a, b, c, newE, e, f, g);
        }

        for (var index = aligned; index < 64; index += 8)
        {
            var rotE = (ulong)e * 0x100000001UL;
            var rotA = (ulong)a * 0x100000001UL;
            var t1 = unchecked(h
                               + (uint)((rotE >> 6) ^ (rotE >> 11) ^ (rotE >> 25))
                               + (g ^ (e & (f ^ g)))
                               + constants[index] + words[index]);
            d = unchecked(d + t1);
            h = unchecked(t1 + (uint)((rotA >> 2) ^ (rotA >> 13) ^ (rotA >> 22))
                              + ((a & b) | (c & (a | b))));

            rotE = (ulong)d * 0x100000001UL;
            rotA = (ulong)h * 0x100000001UL;
            t1 = unchecked(g
                           + (uint)((rotE >> 6) ^ (rotE >> 11) ^ (rotE >> 25))
                           + (f ^ (d & (e ^ f)))
                           + constants[index + 1] + words[index + 1]);
            c = unchecked(c + t1);
            g = unchecked(t1 + (uint)((rotA >> 2) ^ (rotA >> 13) ^ (rotA >> 22))
                              + ((h & a) | (b & (h | a))));

            rotE = (ulong)c * 0x100000001UL;
            rotA = (ulong)g * 0x100000001UL;
            t1 = unchecked(f
                           + (uint)((rotE >> 6) ^ (rotE >> 11) ^ (rotE >> 25))
                           + (e ^ (c & (d ^ e)))
                           + constants[index + 2] + words[index + 2]);
            b = unchecked(b + t1);
            f = unchecked(t1 + (uint)((rotA >> 2) ^ (rotA >> 13) ^ (rotA >> 22))
                              + ((g & h) | (a & (g | h))));

            rotE = (ulong)b * 0x100000001UL;
            rotA = (ulong)f * 0x100000001UL;
            t1 = unchecked(e
                           + (uint)((rotE >> 6) ^ (rotE >> 11) ^ (rotE >> 25))
                           + (d ^ (b & (c ^ d)))
                           + constants[index + 3] + words[index + 3]);
            a = unchecked(a + t1);
            e = unchecked(t1 + (uint)((rotA >> 2) ^ (rotA >> 13) ^ (rotA >> 22))
                              + ((f & g) | (h & (f | g))));

            rotE = (ulong)a * 0x100000001UL;
            rotA = (ulong)e * 0x100000001UL;
            t1 = unchecked(d
                           + (uint)((rotE >> 6) ^ (rotE >> 11) ^ (rotE >> 25))
                           + (c ^ (a & (b ^ c)))
                           + constants[index + 4] + words[index + 4]);
            h = unchecked(h + t1);
            d = unchecked(t1 + (uint)((rotA >> 2) ^ (rotA >> 13) ^ (rotA >> 22))
                              + ((e & f) | (g & (e | f))));

            rotE = (ulong)h * 0x100000001UL;
            rotA = (ulong)d * 0x100000001UL;
            t1 = unchecked(c
                           + (uint)((rotE >> 6) ^ (rotE >> 11) ^ (rotE >> 25))
                           + (b ^ (h & (a ^ b)))
                           + constants[index + 5] + words[index + 5]);
            g = unchecked(g + t1);
            c = unchecked(t1 + (uint)((rotA >> 2) ^ (rotA >> 13) ^ (rotA >> 22))
                              + ((d & e) | (f & (d | e))));

            rotE = (ulong)g * 0x100000001UL;
            rotA = (ulong)c * 0x100000001UL;
            t1 = unchecked(b
                           + (uint)((rotE >> 6) ^ (rotE >> 11) ^ (rotE >> 25))
                           + (a ^ (g & (h ^ a)))
                           + constants[index + 6] + words[index + 6]);
            f = unchecked(f + t1);
            b = unchecked(t1 + (uint)((rotA >> 2) ^ (rotA >> 13) ^ (rotA >> 22))
                              + ((c & d) | (e & (c | d))));

            rotE = (ulong)f * 0x100000001UL;
            rotA = (ulong)b * 0x100000001UL;
            t1 = unchecked(a
                           + (uint)((rotE >> 6) ^ (rotE >> 11) ^ (rotE >> 25))
                           + (h ^ (f & (g ^ h)))
                           + constants[index + 7] + words[index + 7]);
            e = unchecked(e + t1);
            a = unchecked(t1 + (uint)((rotA >> 2) ^ (rotA >> 13) ^ (rotA >> 22))
                              + ((b & c) | (d & (b | c))));
        }

        return new[] { a, b, c, d, e, f, g, h };
    }

    private static byte[] Sha256Digest(byte[] data)
    {
        if (data.Length < 7)
            throw new ArgumentException("令牌数据至少需要 7 个字节。", nameof(data));

        var length = 57 + data.Length;
        var padLength = (55 - length) % 64;
        if (padLength < 0)
            padLength += 64;

        var tailLength = data.Length - 7;
        var padded = new byte[tailLength + 1 + padLength + 8];
        Array.Copy(data, 7, padded, 0, tailLength);
        padded[tailLength] = 0x80;
        BinaryPrimitives.WriteUInt64BigEndian(
            padded.AsSpan(padded.Length - 8), (ulong)length * 8);

        var state = Sha256Init(data.AsSpan(0, 7));
        var words = new uint[64];

        for (var offset = 0; offset < padded.Length; offset += 64)
        {
            for (var i = 0; i < 16; i++)
                words[i] = BinaryPrimitives.ReadUInt32BigEndian(padded.AsSpan(offset + i * 4));

            ExpandSchedule(words, 16);
            var working = Sha256Rounds(state, words, 0);
            for (var i = 0; i < 8; i++)
                state[i] = unchecked(state[i] + working[i]);
        }

        var digest = new byte[32];
        for (var i = 0; i < 8; i++)
            BinaryPrimitives.WriteUInt32BigEndian(digest.AsSpan(i * 4), state[i]);
        return digest;
    }

    private static uint[] WordsLittleEndian(byte[] data)
    {
        var paddedLength = (data.Length + 3) / 4 * 4;
        var words = new uint[paddedLength / 4];
        for (var i = 0; i < words.Length; i++)
        {
            var offset = i * 4;
            var remaining = data.Length - offset;
            uint word = 0;
            if (remaining > 0) word |= data[offset];
            if (remaining > 1) word |= (uint)data[offset + 1] << 8;
            if (remaining > 2) word |= (uint)data[offset + 2] << 16;
            if (remaining > 3) word |= (uint)data[offset + 3] << 24;
            words[i] = word;
        }

        if (words.Length % 2 == 1)
            Array.Resize(ref words, words.Length + 1);
        return words;
    }

    private static (uint, uint) Cs64Digest(byte[] data, byte[] digest)
    {
        var keyA = BinaryPrimitives.ReadUInt32LittleEndian(digest) | 1u;
        var keyB = BinaryPrimitives.ReadUInt32LittleEndian(digest.AsSpan(4)) | 1u;

        var factors = new[]
        {
            unchecked(keyA * Cs64Factor),
            unchecked(keyB * Cs64Factor)
        };

        var terms = new List<uint>(Cs64Coefficients.Length + data.Length / 4 + 2);
        var offsets = new List<uint>(terms.Capacity);
        for (var i = 0; i < Cs64Coefficients.Length; i++)
        {
            terms.Add(unchecked(Cs64Coefficients[i].Coefficient * factors[i % 2]));
            offsets.Add(Cs64Coefficients[i].Offset);
        }

        var salted = new byte[data.Length + 1];
        Array.Copy(data, 0, salted, 1, data.Length);
        var words = WordsLittleEndian(salted);

        for (var i = 0; i < words.Length; i++)
        {
            var term = unchecked(words[i] * (i % 2 == 0 ? keyA : keyB));
            var offset = unchecked(Rol16(words[i]) * (i % 2 == 0 ? 0xEF0569FB : 0xC31713DB));
            if (i == 0)
            {
                term = unchecked(term + Cs64Adjustment0 * factors[0]);
                offset = unchecked(offset + Cs64Adjustment1);
            }

            terms.Add(term);
            offsets.Add(offset);
        }

        uint swapAcc = 0, swapLast = 0, state = 0, acc = 0;
        for (var i = 0; i < terms.Count; i += 2)
        {
            var x = terms[i];
            var y = terms[i + 1];

            var t = Rol16(unchecked(offsets[i] + x));
            var q = unchecked(t * 0x76F50F34);
            swapAcc = unchecked(swapAcc + unchecked(Rol16(q) * 0xC3EFEA97 + q));

            t = Rol16(unchecked(offsets[i + 1] + y));
            q = unchecked(t * 0x1881CE3C);
            swapLast = unchecked(Rol16(q) * 0x35BD1EC9 + q);
            swapAcc = unchecked(swapAcc + swapLast);

            state = unchecked(state * keyA + x);
            state = unchecked(Rol16(state) * 0xCF98B111);
            state = unchecked(Rol16(state) * 0x87085B9F);
            state = unchecked(Rol16(state) * 0x12CEB96D);
            state = unchecked(Rol16(state) * 0x257E1D83);
            acc = unchecked(acc + state);

            t = unchecked(state * keyB + y);
            t = unchecked(Rol16(t) * 0xA27416F5);
            t = unchecked(Rol16(t) * 0xD38396FF);
            state = unchecked(Rol16(unchecked(Rol16(t) * 0x7C932B89)) * 0xBFA49F69);
            acc = unchecked(acc + state);
        }

        return (swapLast ^ state, swapAcc ^ acc);
    }
}
