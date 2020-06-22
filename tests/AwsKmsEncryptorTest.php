<?php

declare(strict_types=1);

namespace BrighteCapital\AwsKmsEncryptor\Tests;

use Aws\Kms\KmsClient;
use Aws\Result;
use BrighteCapital\AwsKmsEncryptor\AwsKmsEncryptor;

/** @coversDefaultClass \BrighteCapital\AwsKmsEncryptor\AwsKmsEncryptor */
class AwsKmsEncryptorTest extends \PHPUnit\Framework\TestCase
{
    /** @var \Aws\Kms\KmsClient */
    private $client;

    /** @var string */
    private $key;

    /** @var \BrighteCapital\AwsKmsEncryptor\AwsKmsEncryptor */
    private $encryptor;

    protected function setUp(): void
    {
        parent::setUp();
        $this->client = $this->createMock(KmsClient::class);
        $this->key = 'testkey';
        $this->encryptor = new AwsKmsEncryptor($this->key);
        $this->encryptor->setKmsClient($this->client);
    }

    /**
     * @covers ::encrypt
     * @covers ::__construct
     * @covers ::setKmsClient
     **/
    public function testEncrypt(): void
    {
        $result = $this->createMock(Result::class);
        $result->expects(static::once())->method('get')->with('CiphertextBlob')->willReturn('ciphertext');
        $this->client->expects(static::once())->method('__call')->with('encrypt', [
            [
                'KeyId' => 'testkey',
                'Plaintext' => 'teststring',
            ]])->willReturn($result);
        $this->assertEquals(base64_encode('ciphertext'), $this->encryptor->encrypt('teststring'));
    }

    /**
     * @covers ::decrypt
     * @covers ::__construct
     * @covers ::setKmsClient
     **/
    public function testDecrypt(): void
    {
        $result = $this->createMock(Result::class);
        $result->expects(static::once())->method('get')->with('Plaintext')->willReturn('teststring');
        $this->client->expects(static::once())->method('__call')->with('decrypt', [
            [
                'CiphertextBlob' => base64_decode('ciphertext'),
            ]])->willReturn($result);
        $this->assertEquals('teststring', $this->encryptor->decrypt('ciphertext'));
    }
}
