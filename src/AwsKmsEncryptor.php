<?php

declare(strict_types=1);

namespace BrighteCapital\AwsKmsEncryptor;

use Aws\Kms\KmsClient;

//phpcs:disable SlevomatCodingStandard.TypeHints.TypeHintDeclaration.MissingParameterTypeHint

class AwsKmsEncryptor implements \Ambta\DoctrineEncryptBundle\Encryptors\EncryptorInterface
{
    /** @var \Aws\Kms\KmsClient */
    private $client;

    /** @var string */
    private $key;

    /**
     * @param string $key ID of encryption key
     * @Inject({"settings.encryptionKeyId"})
     **/
    public function __construct(string $key)
    {
        $this->key = $key;
    }

    public function setKmsClient(KmsClient $client): void
    {
        $this->client = $client;
    }

    /** @param string $string */
    public function encrypt($string): string
    {
        $result = $this->client->encrypt([
            'KeyId' => $this->key,
            'Plaintext' => $string,
        ]);

        return base64_encode($result->get('CiphertextBlob'));
    }

    /** @param string $string */
    public function decrypt($string): string
    {
        $result = $this->client->decrypt([
            'CiphertextBlob' => base64_decode($string),
        ]);

        return $result->get('Plaintext');
    }
}
