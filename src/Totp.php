<?php

declare(strict_types=1);

namespace Ph20sr\Totp;

/**
 * TOTP (RFC 6238) sobre HOTP (RFC 4226). Compatível com Google
 * Authenticator, Microsoft Authenticator, Authy, 1Password e Bitwarden.
 *
 *     $secret = Totp::generateSecret();                 // guarde (cifrado) no usuário
 *     $uri = Totp::uri($secret, 'maria@cliente.com', 'Vynex');   // vira QR Code
 *     $step = Totp::verify($secret, $codigoDigitado, lastUsedStep: $user->totp_last_step);
 *     if ($step !== null) { $user->totp_last_step = $step; ... }
 */
final class Totp
{
    public const PERIOD = 30;
    public const DIGITS = 6;

    /** Segredo aleatório em base32 (160 bits, o recomendado pela RFC 4226). */
    public static function generateSecret(int $bytes = 20): string
    {
        if ($bytes < 16) {
            throw new \InvalidArgumentException('Use pelo menos 16 bytes (128 bits)');
        }
        return Base32::encode(random_bytes($bytes));
    }

    /** HOTP: código para um contador. $key são os bytes do segredo. */
    public static function hotp(string $key, int $counter, int $digits = self::DIGITS, string $algo = 'sha1'): string
    {
        if (!in_array($algo, ['sha1', 'sha256', 'sha512'], true)) {
            throw new \InvalidArgumentException("Algoritmo não suportado: {$algo}");
        }
        if ($digits < 6 || $digits > 8) {
            throw new \InvalidArgumentException('Use de 6 a 8 dígitos');
        }
        $hash = hash_hmac($algo, pack('J', $counter), $key, true);
        $offset = ord($hash[strlen($hash) - 1]) & 0x0f;
        $binary = ((ord($hash[$offset]) & 0x7f) << 24)
            | (ord($hash[$offset + 1]) << 16)
            | (ord($hash[$offset + 2]) << 8)
            | ord($hash[$offset + 3]);
        return str_pad((string) ($binary % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
    }

    /** Passo de tempo (janela de 30 s) de um instante. */
    public static function step(int $timestamp, int $period = self::PERIOD): int
    {
        return intdiv($timestamp, $period);
    }

    /** Código atual de um segredo base32. */
    public static function now(string $secret, ?int $timestamp = null, int $digits = self::DIGITS, string $algo = 'sha1'): string
    {
        return self::hotp(Base32::decode($secret), self::step($timestamp ?? time()), $digits, $algo);
    }

    /**
     * Confere o código digitado. Aceita `window` passos antes e depois
     * (relógio do celular adiantado ou atrasado) e REJEITA reuso: um código
     * já aceito (passo <= lastUsedStep) não vale de novo, mesmo dentro dos 30 s.
     *
     * @return int|null o passo aceito (grave-o como lastUsedStep), ou null se inválido
     */
    public static function verify(
        string $secret,
        string $code,
        ?int $timestamp = null,
        int $window = 1,
        ?int $lastUsedStep = null,
        int $digits = self::DIGITS,
        string $algo = 'sha1',
    ): ?int {
        $code = preg_replace('/\s+/', '', $code) ?? '';
        if (!preg_match('/^\d{' . $digits . '}$/', $code)) {
            return null;
        }
        $key = Base32::decode($secret);
        $current = self::step($timestamp ?? time());
        $accepted = null;
        // Percorre a janela inteira (tempo constante) em vez de parar no primeiro acerto
        for ($i = -$window; $i <= $window; $i++) {
            $step = $current + $i;
            if (hash_equals(self::hotp($key, $step, $digits, $algo), $code) && $accepted === null) {
                $accepted = $step;
            }
        }
        if ($accepted === null || ($lastUsedStep !== null && $accepted <= $lastUsedStep)) {
            return null;
        }
        return $accepted;
    }

    /**
     * URI otpauth:// para gerar o QR Code de cadastro no app.
     */
    public static function uri(string $secret, string $account, string $issuer, int $digits = self::DIGITS, string $algo = 'sha1'): string
    {
        $label = rawurlencode($issuer) . ':' . rawurlencode($account);
        $query = http_build_query([
            'secret' => strtoupper(preg_replace('/[\s=]/', '', $secret) ?? ''),
            'issuer' => $issuer,
            'algorithm' => strtoupper($algo),
            'digits' => $digits,
            'period' => self::PERIOD,
        ], '', '&', PHP_QUERY_RFC3986);
        return "otpauth://totp/{$label}?{$query}";
    }
}
