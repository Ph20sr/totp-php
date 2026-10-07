<?php

declare(strict_types=1);

namespace Ph20sr\Totp;

/** Base32 (RFC 4648), o formato dos segredos lidos pelos apps autenticadores. */
final class Base32
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function encode(string $bytes): string
    {
        $bits = '';
        foreach (str_split($bytes) as $c) {
            $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::ALPHABET[bindec(str_pad($chunk, 5, '0'))];
        }
        return $out;
    }

    /** Aceita minúsculas, espaços e "=" (como os usuários costumam digitar). */
    public static function decode(string $text): string
    {
        $clean = strtoupper(preg_replace('/[\s=-]/', '', $text) ?? '');
        if ($clean === '' || strspn($clean, self::ALPHABET) !== strlen($clean)) {
            throw new \InvalidArgumentException('Segredo base32 inválido');
        }
        $bits = '';
        foreach (str_split($clean) as $c) {
            $bits .= str_pad(decbin(strpos(self::ALPHABET, $c)), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $out .= chr(bindec($byte));
            }
        }
        return $out;
    }
}
