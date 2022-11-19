<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;
use App\Entity\User;
use DateTime;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Component\HttpFoundation\Request;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;

class ApiUserController extends AbstractController
{
    #[Route('/api/login', name: 'app_login')]
    public function logUser(#[CurrentUser] ?User $username, Request $request, ManagerRegistry $doctrine, UserPasswordHasherInterface $passwordHasher, JWTTokenManagerInterface $JWTManager): JsonResponse
      {
        $entity_manager = $doctrine->getManager();
        $username = $request->get("username");
        $password = $request->get("password");
        $token = "";

         //verification du username
        $get_user= $entity_manager->getRepository(User::class)->findOneBy(['username' => $username]);
    
        if($get_user == null){
        //message d'erreur
        return $this->json([
            "message" => "user not exist"
        ], JsonResponse::HTTP_UNAUTHORIZED);
        }

        //  $signature = $this->signatureUtil->verifySignature($data, $privateKey);

         //verification du mdp
        if(password_verify($password, $get_user->getPassword())){
                //si ca correspond on genere le token
            $token = substr($JWTManager->create($get_user), 100, 150); // je récupère les 50 premiers charactère à partir du 100eme de mon token sinon c'est trop long
            $get_user->setToken($token);
            $entity_manager->persist($get_user);
            $entity_manager->flush();
        } else {

            return $this->json([
                "message" => "user not exist"
                ], JsonResponse::HTTP_UNAUTHORIZED);
        }
         
        return $this->json([
            'username'  => $username,
            'token' => $token,
        ], JsonResponse::HTTP_OK);
    }


    #[Route('/api/register', name: 'app_api_register')]
    public function registerUser(Request $request, ManagerRegistry $doctrine, UserPasswordHasherInterface $password_hasher, JWTTokenManagerInterface $JWTManager): JsonResponse
      {
        $entity_manager = $doctrine->getManager();
        $user = new User();
        // les infos dont on aura besoin : username, mdp(contraintes), email
        $username = $request->get("username");
        $password = $request->get("password");
        $email = $request->get("email");
        $token = "";

         //verification du username si il n'est pas deja pris
         $get_username = $entity_manager->getRepository(User::class)->findOneBy(['username' => $username]);

         if($get_username != null){
            //message d'erreur
            return $this->json([
                "message" => "username already exist"
            ], JsonResponse::HTTP_UNAUTHORIZED);
         }

         //ajout du mdp en hashé
         $hashed_password = $password_hasher->hashPassword(
            $user,
            $password
        );
        $datetime = new DateTime();
        //si c'est bon faudra ajouter ses infos en BDD
        $user->setUsername($username);
        $user->setPassword($hashed_password);
        $user->setEmail($email);
        $user->setRoles(array("ROLE_USER"));
        $user->setLastConnection($datetime);

        $token = substr($JWTManager->create($user), 100, 150); // je récupère les 50 premiers charactère à partir du 100eme de mon token sinon c'est trop long
        $user->setToken($token);

        $entity_manager->persist($user);
        $entity_manager->flush();

        return $this->json([
            "message" => "done"
        ], JsonResponse::HTTP_OK);
    }

    #[Route('/api/renewToken', name: 'app_api_renew_token')]
    public function renewToken(Request $request, ManagerRegistry $doctrine, JWTTokenManagerInterface $JWTManager){

        $entity_manager = $doctrine->getManager();
        $actual_token = $request->get("token");
        $token = "";

        //verification du username
        $get_user_token= $entity_manager->getRepository(User::class)->findOneBy(['token' => $actual_token]);

        if($get_user_token == null){
            //message d'erreur
            return $this->json([
                "message" => "token not found"
            ], JsonResponse::HTTP_UNAUTHORIZED);

         } else {

            $token = substr($JWTManager->create($get_user_token), 100, 150); // je récupère les 50 premiers charactère à partir du 100eme de mon token sinon c'est trop long
            $get_user_token->setToken($token);
            $entity_manager->persist($get_user_token);
            $entity_manager->flush();
        }
         
        return $this->json([
            'token' => $token,
        ], JsonResponse::HTTP_OK);
    }


}
