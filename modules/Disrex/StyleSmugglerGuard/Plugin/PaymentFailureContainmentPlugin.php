<?php
/**
 * StyleSmuggler interim mitigation. Remove once Adobe ships an official fix.
 * Advisory: https://sansec.io/research/stylesmuggler
 * Adapted from brideo / Upturn (https://github.com/brideo/stylesmuggler-patch, MIT),
 * whose note credits Sam James (https://samdjames.uk) for the containment idea.
 */
declare(strict_types=1);

namespace Disrex\StyleSmugglerGuard\Plugin;

use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Sales\Model\Service\PaymentFailuresService;
use Psr\Log\LoggerInterface;

/**
 * Sansec's 2026-09-06 update confirms the code runs while Magento renders the
 * "Payment Transaction Failed Reminder" email — nobody has to open it, the render is the
 * trigger. Short-circuiting that one email's render removes one concrete trigger path.
 *
 * DEFAULT OFF, and it is a real trade-off: while enabled, the merchant stops receiving
 * legitimate failed-payment notifications. Only enable it on a store whose owner has
 * agreed to that, and record the agreement. This closes one trigger, not the underlying
 * vulnerability; it is not a substitute for the sink patch or disable_functions.
 */
class PaymentFailureContainmentPlugin
{
    private const CONFIG_PATH = 'disrex_stylesmuggler/guard/payment_failure_containment_enabled';

    /** @var LoggerInterface */
    private $logger;

    /** @var ScopeConfigInterface */
    private $scopeConfig;

    public function __construct(LoggerInterface $logger, ScopeConfigInterface $scopeConfig)
    {
        $this->logger = $logger;
        $this->scopeConfig = $scopeConfig;
    }

    /**
     * @param PaymentFailuresService $subject
     * @param callable $proceed
     * @param mixed ...$args
     * @return PaymentFailuresService
     */
    public function aroundHandle(PaymentFailuresService $subject, callable $proceed, ...$args)
    {
        if (!$this->scopeConfig->isSetFlag(self::CONFIG_PATH)) {
            return $proceed(...$args);
        }

        $this->logger->warning(
            'StyleSmugglerGuard: suppressed Payment Transaction Failed Reminder render '
            . '(payment_failure_containment_enabled=1). The merchant will NOT receive this '
            . 'notification while this is on.'
        );

        return $subject;
    }
}
