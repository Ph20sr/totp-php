<?php

declare(strict_types=1);

namespace Ph20sr\Totp\Tests;

use Ph20sr\Totp\Base32;
use Ph20sr\Totp\RecoveryCodes;
use Ph20sr\Totp\Totp;
use PHPUnit\Framework\TestCase;

final class TotpTest extends TestCase
{
    /** RFC 4226, Apêndice D: segredo ASCII "12345678901234567890", contadores 0–9. */
    public function testHotpRfc4226Vectors(): void
    {
        $expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
        foreach ($expected as $counter => $code) {
            $this->assertSame($code, Totp::hotp('12345678901234567890', $counter), "contador {$counter}");
        }
    }

    /** RFC 6238, Apêndice B: 8 dígitos, SHA-1/256/512. */
    public function testTotpRfc6238Vectors(): void
    {
        $keys = [
            'sha1' => '12345678901234567890',
            'sha256' => '12345678901234567890123456789012',
            'sha512' => '1234567890123456789012345678901234567890123456789012345678901234',
        ];
        $vectors = [
            [59, '94287082', '46119246', '90693936'],
            [1111111109, '07081804', '68084774', '25091201'],
            [1111111111, '14050471', '67062674', '99943326'],
            [1234567890, '89005924', '91819424', '93441116'],
            [2000000000, '69279037', '90698825', '38618901'],
            [20000000000, '65353130', '77737706', '47863826'],
        ];
        foreach ($vectors as [$t, $sha1, $sha256, $sha512]) {
            $step = Totp::step($t);
            $this->assertSame($sha1, Totp::hotp($keys['sha1'], $step, 8, 'sha1'), "SHA1 T={$t}");
            $this->assertSame($sha256, Totp::hotp($keys['sha256'], $step, 8, 'sha256'), "SHA256 T={$t}");
            $this->assertSame($sha512, Totp::hotp($keys['sha512'], $step, 8, 'sha512'), "SHA512 T={$t}");
        }
    }

    public function testBase32RoundTripAndRfc4648Vectors(): void
    {
        $this->assertSame('MZXW6YTBOI', Base32::encode('foobar'));
        $this->assertSame('foobar', Base32::decode('mzxw 6ytb oi======'));
        $bytes = random_bytes(20);
        $this->assertSame($bytes, Base32::decode(Base32::encode($bytes)));
        $this->expectException(\InvalidArgumentException::class);
        Base32::decode('não é base32!');
    }

    public function testVerifyWithWindowAndReplayProtection(): void
    {
        $secret = Base32::encode('12345678901234567890');
        $t = 1_791_300_000;
        $code = Totp::now($secret, $t);

        $step = Totp::verify($secret, $code, $t);
        $this->assertSame(Totp::step($t), $step);

        // Relógio do celular 30 s atrasado: ainda aceita (janela = 1)
        $this->assertNotNull(Totp::verify($secret, Totp::now($secret, $t - 30), $t));
        // 90 s fora: rejeita
        $this->assertNull(Totp::verify($secret, Totp::now($secret, $t - 90), $t));

        // O mesmo código não pode ser usado duas vezes
        $this->assertNull(Totp::verify($secret, $code, $t + 5, lastUsedStep: $step));
        // Código anterior ao último usado também não
        $this->assertNull(Totp::verify($secret, Totp::now($secret, $t - 30), $t, lastUsedStep: $step));

        $this->assertNull(Totp::verify($secret, '12345', $t), 'tamanho errado');
        $this->assertNull(Totp::verify($secret, 'abcdef', $t));
        $this->assertSame($step, Totp::verify($secret, substr($code, 0, 3) . ' ' . substr($code, 3), $t), 'aceita "123 456"');
    }

    public function testGenerateSecretAndUri(): void
    {
        $secret = Totp::generateSecret();
        $this->assertSame(32, strlen($secret), '20 bytes = 32 caracteres base32');
        $this->assertSame(20, strlen(Base32::decode($secret)));

        $uri = Totp::uri('JBSWY3DPEHPK3PXP', 'maria@cliente.com', 'Vynex CRM');
        $this->assertSame(
            'otpauth://totp/Vynex%20CRM:maria%40cliente.com?secret=JBSWY3DPEHPK3PXP&issuer=Vynex%20CRM&algorithm=SHA1&digits=6&period=30',
            $uri,
        );
        $this->expectException(\InvalidArgumentException::class);
        Totp::generateSecret(10);
    }

    public function testRecoveryCodesAreSingleUseFriendlyAndHashed(): void
    {
        ['codes' => $codes, 'hashes' => $hashes] = RecoveryCodes::generate(5);
        $this->assertCount(5, $codes);
        $this->assertSame(1, preg_match('/^[A-HJKMNP-Z2-9]{5}-[A-HJKMNP-Z2-9]{5}$/', $codes[0]), 'sem 0, O, 1, I, L');
        $this->assertStringNotContainsString($codes[0], implode(',', $hashes), 'só hashes');

        $index = RecoveryCodes::consume(strtolower(str_replace('-', ' ', $codes[2])), $hashes);
        $this->assertSame(2, $index, 'aceita minúsculas e espaço no lugar do hífen');

        unset($hashes[$index]);
        $this->assertNull(RecoveryCodes::consume($codes[2], array_values($hashes)), 'não vale duas vezes');
        $this->assertNull(RecoveryCodes::consume('AAAAA-AAAAA', $hashes));
    }
}
