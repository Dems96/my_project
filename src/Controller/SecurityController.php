<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends AbstractController
{
    // #[Route(path: 'api/login', name: 'app_login')]
    // public function login(AuthenticationUtils $authenticationUtils): JsonResponse
    // {
    //     if ($this->getUser()) {
    //             return $this->json([
    //             'username'  => "",
    //             'token' => "",
    //         ], JsonResponse::HTTP_OK);
    //     }

    //     // get the login error if there is one
    //     $error = $authenticationUtils->getLastAuthenticationError();
    //     // last username entered by the user
    //     $lastUsername = $authenticationUtils->getLastUsername();
    //     dump($error);
    //     return $this->json([
    //         'username'  => "",
    //         'token' => "",
    //     ], JsonResponse::HTTP_OK);
    // }

    // #[Route(path: '/logout', name: 'app_logout')]
    // public function logout(): void
    // {
    //     throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    // }
}
