<?php

namespace App\Controller\User;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\DependencyInjection\Attribute\Target;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\UriSigner;
use Symfony\Component\Mailer\Header\MetadataHeader;
use Symfony\Component\Mailer\Header\TagHeader;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

use function Symfony\Component\Clock\now;

final class VerificationController extends AbstractController
{
    private const EXPIRES_AFTER = 3600 * 24; // 24 hours
    private const SESSION_ID = 'verification_id';

    public function __construct(
        private UriSigner $uriSigner,
        private MailerInterface $mailer,
    ) {
    }

    #[Route('/send-verification', name: 'send_verification', methods: 'POST')]
    public function sendVerification(
        #[CurrentUser]
        User $user,

        #[Target('verifyEmailLimiter')]
        RateLimiterFactory $rateLimiter, // todo switch to RateLimiterInterface in 7.3
    ): Response {
        if ($user->isVerified()) {
            return $this->redirectToRoute('homepage');
        }

        if (!$rateLimiter->create($user->getEmail())->consume()->isAccepted()) {
            $this->addFlash('warning', 'You recently requested an account verification. Please check your email for the link to verify your account.');

            return $this->redirectToRoute('homepage');
        }

        $this->sendVerificationLink($user);
        $this->addFlash('note', sprintf('A verification link has been sent to %s.', $user->getEmail()));

        return $this->redirectToRoute('homepage');
    }

    #[Route('/verify/{id<\d+>}', name: 'verify_email')]
    public function verify(
        Request $request,
        UserRepository $users,
        EntityManagerInterface $em,
        Security $security,
        ?int $id = null,
    ): Response {
        if (null !== $id) {
            return $this->addIdToSessionAndRedirect($request, $id);
        }

        if (!$user = $users->find($request->getSession()->get(self::SESSION_ID, 0))) {
            throw $this->createNotFoundException('User not found');
        }

        if ($user->isVerified()) {
            $this->addFlash('warning', 'This verification link has already been used.');

            return $this->redirectToRoute('homepage');
        }

        $user->verify();
        $em->flush();
        $this->addFlash('success', 'Your email has been verified successfully.');
        $request->getSession()->remove(self::SESSION_ID);

        return $security->login($user, 'form_login');
    }

    private function addIdToSessionAndRedirect(Request $request, int $id): Response
    {
        if (!$this->uriSigner->checkRequest($request)) {
            $this->addFlash('error', 'The verification link is invalid or has expired, try resending.');

            return $this->redirectToRoute('homepage');
        }

        $request->getSession()->set(self::SESSION_ID, $id);

        return $this->redirectToRoute('verify_email');
    }

    private function sendVerificationLink(User $user): void
    {
        $expires = now()->modify(sprintf('+%d seconds', self::EXPIRES_AFTER));
        $link = $this->uriSigner->sign(
            $this->generateUrl(
                'verify_email',
                ['id' => $user->getId()],
                UrlGeneratorInterface::ABSOLUTE_URL
            ),
            $expires
        );

        $message = (new TemplatedEmail())
            ->to($user->getEmailAddress())
            ->subject('Email Verification')
            ->htmlTemplate('email/verify_email.html.twig')
            ->context([
                'user' => $user,
                'link' => $link,
                'expires' => $expires,
            ])
        ;
        $message->getHeaders()->add(new TagHeader('verify-email'));
        $message->getHeaders()->add(new MetadataHeader('link', $link));

        $this->mailer->send($message);
    }
}
