<?php

declare(strict_types=1);

namespace Ezone;

class EzoneException extends \RuntimeException
{
    public function __construct(private int $statusCode, string $message)
    {
        parent::__construct($message);
    }

    public function getStatusCode(): int { return $this->statusCode; }
}
