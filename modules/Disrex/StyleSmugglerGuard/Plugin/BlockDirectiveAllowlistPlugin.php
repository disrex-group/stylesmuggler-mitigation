<?php
/**
 * StyleSmuggler interim mitigation. Remove once Adobe ships an official fix.
 * Advisory: https://sansec.io/research/stylesmuggler
 * Adapted from brideo / Upturn (https://github.com/brideo/stylesmuggler-patch, MIT).
 */
declare(strict_types=1);

namespace Disrex\StyleSmugglerGuard\Plugin;

use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\Filter\Template;
use Psr\Log\LoggerInterface;

/**
 * StyleSmuggler stage 2 walks an object-injection chain through the template filter's
 * {{block ...}} directive into Magento's DI code scanners, which include()/require_once()
 * a caller-supplied path. This rejects any {{block ...}} whose class/type names a
 * DI/Setup/Code namespace that has no business in a storefront or email template.
 *
 * Hooks Framework\Filter\Template::filter() (a real, stable public method across 2.4.x)
 * and scans the raw string before tokenisation, so it does not depend on the
 * version-specific internal directive-handler class. The regex is intentionally narrow:
 * it only blocks block directives that reference the dangerous namespaces, so ordinary
 * {{block class="Magento\Cms\Block\..."}} usage in CMS and email content is untouched.
 */
class BlockDirectiveAllowlistPlugin
{
    private const CONFIG_PATH = 'disrex_stylesmuggler/guard/block_directive_allowlist_enabled';

    private const DISALLOWED = '/\{\{\s*block\b[^}]*\b(?:class|type)\s*=\s*["\']\s*\\\\?Magento\\\\(?:Setup|Framework\\\\(?:ObjectManager|Code))\\\\/i';

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
     * @param Template $subject
     * @param callable $proceed
     * @param string $value
     * @return string
     */
    public function aroundFilter(Template $subject, callable $proceed, $value)
    {
        if (!$this->scopeConfig->isSetFlag(self::CONFIG_PATH)) {
            return $proceed($value);
        }

        if (is_string($value) && preg_match(self::DISALLOWED, $value)) {
            $this->logger->critical(
                'StyleSmugglerGuard: blocked a {{block}} directive naming a DI/Setup/Code '
                . 'namespace (StyleSmuggler stage 2). Returning empty output for this render.'
            );
            return '';
        }

        return $proceed($value);
    }
}
