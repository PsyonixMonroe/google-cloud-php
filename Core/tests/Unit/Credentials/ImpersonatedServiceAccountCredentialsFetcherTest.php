<?php

namespace Google\Cloud\Core\Credentials\Tests\Unit;

use Google\Cloud\Core\Credentials\ImpersonatedServiceAccountCredentials;
use PHPUnit\Framework\TestCase;

// Creates a standard JSON auth object for testing.
function createISACTestJson()
{
    return [
        'type' => 'impersonated_service_account',
        'service_account_impersonation_url' => 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@test-project.iam.gserviceaccount.com:generateAccessToken',
        'source_credentials' => [
            'client_id' => 'client123',
            'client_secret' => 'clientSecret123',
            'refresh_token' => 'refreshToken123',
            'type' => 'authorized_user',
        ]
    ];
}

class ISACGetServiceAccountNameTest extends TestCase
{
    public function testGetServiceAccountNameEmail()
    {
        $testJson = createISACTestJson();
        $scope = ['scope/1', 'scope/2'];
        $sa = new ImpersonatedServiceAccountCredentials(
            $scope,
            $testJson
        );
        $this->assertEquals('test@test-project.iam.gserviceaccount.com', $sa->getServiceAccount());

    }

    public function testGetServiceAccountNameID()
    {
        $testJson = createISACTestJson();
        $testJson['service_account_impersonation_url'] = 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/1234567890987654321:generateAccessToken';
        $scope = ['scope/1', 'scope/2'];
        $sa = new ImpersonatedServiceAccountCredentials(
            $scope,
            $testJson
        );
        $this->assertEquals('1234567890987654321', $sa->getServiceAccount());
    }

    public function testErrorCredentials()
    {
        $testJson = createISACTestJson();
        $scope = ['scope/1', 'scope/2'];
        $this->expectException();
        new ImpersonatedServiceAccountCredentials($scope, $testJson['source_credentials']);
    }
}
