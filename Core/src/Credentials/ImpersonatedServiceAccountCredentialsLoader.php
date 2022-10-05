<?php

namespace Google\Cloud\Core\Credentials;

use Google\Auth\CredentialLoaderExtension;

class ImpersonatedServiceAccountCredentialsLoader implements CredentialLoaderExtension
{
    /**
     * @inheritDoc
     */
    public function checkSupportedType(array $jsonKey)
    {
        return $jsonKey['type'] == 'impersonated_service_account';
    }

    /**
     * @inheritDoc
     */
    public function createCredentialLoader($scope, array $jsonKey, $defaultScope)
    {
        $anyScope = $scope ?: $defaultScope;
        return new ImpersonatedServiceAccountCredentials($anyScope, $jsonKey);
    }
}
