# totp-php

[![CI](https://github.com/Ph20sr/totp-php/actions/workflows/ci.yml/badge.svg)](https://github.com/Ph20sr/totp-php/actions/workflows/ci.yml)
![PHP](https://img.shields.io/badge/php-%3E%3D8.1-777bb4)
![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)

**Autenticação em dois fatores** para painéis administrativos, CRMs e áreas de cliente em PHP: o código de 6 dígitos do **Google Authenticator, Microsoft Authenticator, Authy, 1Password ou Bitwarden**. Não tem dependências.

Validado contra **todos os vetores de teste oficiais**: RFC 4226 (HOTP) e RFC 6238 (TOTP em SHA-1, SHA-256 e SHA-512).

## O que vem pronto

- Segredo aleatório de 160 bits e **URI `otpauth://`** para gerar o QR Code de cadastro
- Verificação com **tolerância de relógio** (±30 s por padrão)
- **Proteção contra reuso**: o mesmo código não entra duas vezes, mesmo dentro dos 30 s (alguém olhando por cima do ombro não consegue repetir)
- Comparação em tempo constante (`hash_equals`), percorrendo a janela inteira
- **Códigos de recuperação** para quando o celular se perde: uso único, guardados só como hash, sem caracteres confusos (`0/O`, `1/I/L`)
- Aceita o código digitado com espaço (`123 456`)

## Uso

### 1. Ativar o 2FA

```php
use Ph20sr\Totp\{Totp, RecoveryCodes};

$secret = Totp::generateSecret();                       // guarde CIFRADO no usuário (ainda pendente)
$uri = Totp::uri($secret, $user->email, 'Vynex CRM');   // gere o QR Code com qualquer biblioteca de QR
// mostre o QR e o segredo para digitação manual; peça o primeiro código para confirmar:

$step = Totp::verify($secret, $_POST['code']);
if ($step === null) {
    exit('Código inválido');
}
['codes' => $codes, 'hashes' => $hashes] = RecoveryCodes::generate();
$user->update(['totp_secret' => encrypt($secret), 'totp_last_step' => $step, 'recovery_codes' => json_encode($hashes)]);
// mostre $codes UMA vez e peça para o usuário guardar
```

### 2. No login

```php
$step = Totp::verify(decrypt($user->totp_secret), $_POST['code'], lastUsedStep: $user->totp_last_step);

if ($step !== null) {
    $user->update(['totp_last_step' => $step]);     // impede reuso deste código
    login($user);
} elseif (($i = RecoveryCodes::consume($_POST['code'], $hashes = json_decode($user->recovery_codes, true))) !== null) {
    unset($hashes[$i]);                             // código de recuperação: vale uma vez
    $user->update(['recovery_codes' => json_encode(array_values($hashes))]);
    login($user);
} else {
    // erro + rate limit (ex.: ph20sr/rate-limit-php): 6 dígitos são só 1 milhão de combinações
}
```

## Boas práticas

- **Cifre o segredo no banco** (ex.: `sodium_crypto_secretbox`). Quem tem o segredo gera os códigos.
- **Limite as tentativas** de código: sem limite, 1 milhão de combinações é pouco.
- Peça o código de novo para ações sensíveis (trocar e-mail, desativar o 2FA, gerar chave de API).

## Testes

```bash
composer install
vendor/bin/phpunit
```

## Licença

MIT
