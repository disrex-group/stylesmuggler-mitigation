<?php
/**
 * StyleSmuggler interim mitigation. Remove once Adobe ships an official fix.
 * Advisory: https://sansec.io/research/stylesmuggler
 *
 * Adapted from brideo / Upturn (https://github.com/brideo/stylesmuggler-patch, MIT)
 * with one correction: their plugin hooked afterSetTemplateStyles, but setTemplateStyles
 * is a magic setter (DataObject::__call), which Magento's plugin system cannot intercept,
 * so that plugin never fired. This hooks getProcessedTemplate, a real public method, and
 * sanitises the styles there instead. Calling the magic setter to blank the value is fine;
 * only intercepting a magic method fails.
 */
declare(strict_types=1);

namespace Disrex\StyleSmugglerGuard\Plugin;

use Magento\Email\Model\AbstractTemplate;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Psr\Log\LoggerInterface;

/**
 * StyleSmuggler is named for the styles[...] parameter it drives through the email
 * template filter. Legitimate template styles are always plain CSS. Anything carrying a
 * template directive ({{ }}), a PHP open tag, or a class-namespace separator is not CSS
 * and is rejected before getProcessedTemplate() renders it.
 */
class TemplateStylesSanitizerPlugin
{
    private const CONFIG_PATH = 'disrex_stylesmuggler/guard/template_styles_sanitizer_enabled';
    private const MARKERS = '/\{\{|<\?|\\\\[A-Za-z0-9_]+\\\\/';

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
     * @param AbstractTemplate $subject
     * @param array $variables
     * @return array
     */
    public function beforeGetProcessedTemplate(AbstractTemplate $subject, array $variables = [])
    {
        if (!$this->scopeConfig->isSetFlag(self::CONFIG_PATH)) {
            return [$variables];
        }

        // The model injects template_styles into $variables from getTemplateStyles(),
        // so sanitising the stored value covers the common path.
        $styles = $subject->getTemplateStyles();
        if (is_string($styles) && $styles !== '' && preg_match(self::MARKERS, $styles)) {
            $this->reject('template styles');
            $subject->setTemplateStyles('');
        }

        // Cover the case where a caller passes template_styles in directly.
        if (isset($variables['template_styles'])
            && is_string($variables['template_styles'])
            && preg_match(self::MARKERS, $variables['template_styles'])
        ) {
            $this->reject('template_styles variable');
            $variables['template_styles'] = '';
        }

        return [$variables];
    }

    private function reject(string $where): void
    {
        $this->logger->critical(
            'StyleSmugglerGuard: stripped ' . $where
            . ' carrying directive/PHP-tag/namespace markers (possible StyleSmuggler probe)'
        );
    }
}
