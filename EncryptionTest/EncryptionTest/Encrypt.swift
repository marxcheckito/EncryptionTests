//
//  Encrypt.swift
//  Encryption
//
//  Created by Daniel Marx on 15.11.17.
//

import Foundation

typealias Byte = UInt8
typealias Word = UInt32
typealias DWord = UInt64

let shift : [Word] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

let table: [Word] = (0 ..< 64).map { UInt32(0x100000000 * abs(sin(Double($0 + 1)))) }

func F(_ b: Word, _ c: Word, _ d: Word) -> Word {
    return (b & c) | ((~b) & d)
}

func G(_ b: Word, _ c: Word, _ d: Word) -> Word {
    return (b & d) | (c & (~d))
}

func H(_ b: Word, _ c: Word, _ d: Word) -> Word {
    return b ^ c ^ d
}

func I(_ b: Word, _ c: Word, _ d: Word) -> Word {
    return c ^ (b | (~d))
}

func rotateLeft(_ x: Word, by: Word) -> Word {
    return ((x << by) & 0xFFFFFFFF) | (x >> (32 - by))
}

public struct Digest {
    public let bytes: [UInt8]?
    
    public func toString() -> String {
        guard let bytes = bytes else { return "" }
        return bytes.map { String(format:"%02x", $0) }.joined()
    }
}

enum Encrypt {
    
    static func md5(_ value: String) -> Digest {
        
        var a0: Word = 0x67452301 // A
        var b0: Word = 0xefcdab89 // B
        var c0: Word = 0x98badcfe // C
        var d0: Word = 0x10325476 // D
        
        var message = Array(value.utf8)
        
        let originalLength = message.count
        
        message.append(0x80)
        
        while message.count % 64 != 56 {
            message.append(0)
        }
        
        let messageLenBits = DWord(originalLength) * 8
        let lengthBytes = [Byte](repeating: 0, count: 8)
        UnsafeMutablePointer(mutating: lengthBytes).withMemoryRebound(to: DWord.self, capacity: 1, { pointer in
            pointer.pointee = messageLenBits.littleEndian
        })
        
        message += lengthBytes
        
        // split chunks
        let chunks = stride(from: 0, to: message.count, by: 64).map {
            Array(message[$0..<min($0 + 64, message.count)])
        }
        
        chunks.forEach { chunk in
            let pointer = UnsafePointer(chunk).withMemoryRebound(to: Word.self, capacity: 1, { pointer -> UnsafePointer<Word> in
                return pointer
            })
            
            var A: Word = a0
            var B: Word = b0
            var C: Word = c0
            var D: Word = d0
            
            for i in 0..<64 {
                var f: Word = 0
                var g: Int = 0
                
                switch i >> 4 {
                case 0:
                    f = F(B, C, D)
                    g = i
                case 1:
                    f = G(B, C, D)
                    g = ((5*i + 1) % 16)
                case 2:
                    f = H(B, C, D)
                    g = ((3*i + 5) % 16)
                case 3:
                    f = I(B, C, D)
                    g = ((7*i) % 16)
                default:
                    assert(false)
                }
                
                let dTemp = D
                D = C
                C = B
                
                let x = A &+ f &+ table[i] &+ pointer.advanced(by: g).pointee
                
                B = B &+ rotateLeft(x, by: shift[i])
                A = dTemp
            }
            
            a0 = a0 &+ A
            b0 = b0 &+ B
            c0 = c0 &+ C
            d0 = d0 &+ D
        }
        
        let result = [Byte](repeating: 0, count: 16)
        for (i, n) in [a0, b0, c0, d0].enumerated() {
            UnsafeMutablePointer(mutating: result).withMemoryRebound(to: Word.self, capacity: 1, { pointer in
                pointer.advanced(by: i).pointee = n.littleEndian
            })
        }
        
        return Digest(bytes: result)
    }
}
