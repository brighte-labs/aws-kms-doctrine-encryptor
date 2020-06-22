<?php

declare(strict_types=1);

namespace BrighteCapital\AwsKmsEncryptor;

use Ambta\DoctrineEncryptBundle\Encryptors\HaliteEncryptor;
use Aws\Result;

//phpcs:disable SlevomatCodingStandard.TypeHints.TypeHintDeclaration.MissingParameterTypeHint
//phpcs:disable SlevomatCodingStandard.TypeHints.TypeHintDeclaration.MissingReturnTypeHint
class MockKmsClient extends \Aws\Kms\KmsClient
{
    /** @var \Ambta\DoctrineEncryptBundle\Encryptors\HaliteEncryptor */
    private $actualEncryptor;

    public function __construct()
    {
        $this->actualEncryptor = new HaliteEncryptor('encryption_key');
    }

    /**
     * @param string $name
     * @param string[] $args
     * @return \Aws\Result
     **/
    public function __call($name, array $args)
    {
        return $this->$name(...$args);
    }

    /**
     * @param string $data
     * @return \Aws\Result
     **/
    public function encrypt($data)
    {
        $string = $this->actualEncryptor->encrypt($data['Plaintext']);

        return new Result(['CiphertextBlob' => $string]);
    }

    /**
     * @param string $data
     * @return \Aws\Result
     **/
    public function decrypt($data)
    {
        $string = $this->actualEncryptor->decrypt($data['CiphertextBlob']);

        return new Result(['Plaintext' => $string]);
    }
}
