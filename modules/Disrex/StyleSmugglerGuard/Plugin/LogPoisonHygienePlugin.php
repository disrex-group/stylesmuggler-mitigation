<?php
/**
 * StyleSmuggler interim mitigation. Remove once Adobe ships an official fix.
 * Advisory: https://sansec.io/research/stylesmuggler
 * Adapted from brideo / Upturn (https://github.com/brideo/stylesmuggler-patch, MIT).
 */
declare(strict_types=1);

namespace Disrex\StyleSmugglerGuard\Plugin;

use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\Exception\NoSuchEntityException;
use Magento\Store\Model\StoreManager;

/**
 * StyleSmuggler stage 1 poisons a log file by sending input Magento rejects but logs
 * verbatim. The documented example is an invalid store code, which Magento embeds
 * unmodified into a NoSuchEntityException message that reaches var/log/system.log or
 * var/report/<hash>. This strips PHP tag sequences from that message at the store
 * lookup, the single most concretely identified stage-1 sink.
 *
 * This is one sink, not all of them. Stage 1 is fundamentally unfilterable in general
 * (it looks like ordinary broken input), so treat this as narrowing one known path, not
 * closing the class. The layers that actually hold are the DI-scanner sink patch and
 * disable_functions; see the repository root.
 */
class LogPoisonHygienePlugin
{
    private const CONFIG_PATH = 'disrex_stylesmuggler/guard/log_poison_hygiene_enabled';

    /** @var ScopeConfigInterface */
    private $scopeConfig;

    public function __construct(ScopeConfigInterface $scopeConfig)
    {
        $this->scopeConfig = $scopeConfig;
    }

    /**
     * @param StoreManager $subject
     * @param callable $proceed
     * @param string|int|null $storeId
     * @return mixed
     * @throws NoSuchEntityException
     */
    public function aroundGetStore(StoreManager $subject, callable $proceed, $storeId = null)
    {
        try {
            return $proceed($storeId);
        } catch (NoSuchEntityException $e) {
            if (!$this->scopeConfig->isSetFlag(self::CONFIG_PATH)) {
                throw $e;
            }
            $clean = str_replace(['<?php', '<?=', '<?', '?>'], '', $e->getMessage());
            if ($clean === $e->getMessage()) {
                throw $e;
            }
            throw new NoSuchEntityException(__($clean));
        }
    }
}
