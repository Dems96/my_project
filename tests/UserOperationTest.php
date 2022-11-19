<?php

namespace App\Tests;

use ApiPlatform\Core\Bridge\Symfony\Bundle\Test\ApiTestCase;
use PHPUnit\Framework\TestCase;
use App\Entity\User;
use App\Controller\ApiUserController;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\ResponseInterface;

class UserOperationTest extends ApiTestCase
{
    public function testSomething(): void
    {

        $client = self::createClient();
        $client->request('POST', '127.0.0.1:8000/api/login', [
            'json' => [
                'username' => 'dembabalde.db@gmail.com',
                'password' => 'firman'
            ],
        ]);


        $this->assertResponseStatusCodeSame(200);
        // $this->assertTrue($request->getInfo('message'));
        // $data = json_decode($request->getBody(true), true);
    }
}
