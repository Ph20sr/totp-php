<?php

declare(strict_types=1);

namespace Ph20sr\Totp;

/**
 * Códigos de recuperação para quando o usuário perde o celular. Cada um
 * vale UMA vez; guarde só os hashes (como senhas).
 */
final class RecoveryCodes
{
    // Sem 0/O, 1/I/L: fáceis de ler e digitar
    private const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

    /**
     * @return array{codes: list<string>, hashes: list<string>} mostre `codes` uma vez; grave `hashes`
     */
    public static function generate(int $count = 10): array
    {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $raw = '';
            for ($j = 0; $j < 10; $j++) {
                $raw .= self::ALPHABET[random_int(0, strlen(self::ALPHABET) - 1)];
            }
            $codes[] = substr($raw, 0, 5) . '-' . substr($raw, 5);
        }
        return ['codes' => $codes, 'hashes' => array_map(self::hash(...), $codes)];
    }

    public static function normalize(string $code): string
    {
        return strtoupper(preg_replace('/[^0-9A-Za-z]/', '', $code) ?? '');
    }

    public static function hash(string $code): string
    {
        return password_hash(self::normalize($code), PASSWORD_DEFAULT);
    }

    /**
     * Procura o código entre os hashes. Devolve o índice usado (para
     * removê-lo) ou null.
     *
     * @param list<string> $hashes
     */
    public static function consume(string $code, array $hashes): ?int
    {
        $normalized = self::normalize($code);
        if (strlen($normalized) !== 10) {
            return null;
        }
        foreach ($hashes as $i => $hash) {
            if (password_verify($normalized, $hash)) {
                return $i;
            }
        }
        return null;
    }
}
