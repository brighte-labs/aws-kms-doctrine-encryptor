<?php

declare(strict_types=1);

namespace BrighteCapital\AwsKmsEncryptor\Tests;

use Aws\Result;
use BrighteCapital\AwsKmsEncryptor\MockKmsClient;

/** @coversDefaultClass \BrighteCapital\AwsKmsEncryptor\MockKmsClient */
class MockKmsClientTest extends \PHPUnit\Framework\TestCase
{
    /** @var \Aws\Kms\KmsClient */
    private $client;

    protected function setUp(): void
    {
        parent::setUp();
        $this->client = new MockKmsClient();
    }

    /**
     * @covers ::encrypt
     * @covers ::decrypt
     * @covers ::__construct
     * @covers ::__call
     **/
    public function testEncrypt(): void
    {
        $result = $this->client->__call('encrypt', [['Plaintext' => 'string']]);
        self::assertInstanceOf(Result::class, $result);
        self::assertNotEmpty($result->get('CiphertextBlob'));
        $result = $this->client->__call('decrypt', [['CiphertextBlob' => $result->get('CiphertextBlob')]]);
        self::assertInstanceOf(Result::class, $result);
        self::assertEquals('string', $result->get('Plaintext'));
    }
}
