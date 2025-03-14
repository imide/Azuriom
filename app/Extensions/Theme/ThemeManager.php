<?php

namespace Azuriom\Extensions\Theme;

use Azuriom\Extensions\ExtensionManager;
use Azuriom\Extensions\UpdateManager;
use Azuriom\Models\Setting;
use Azuriom\Support\Files;
use Azuriom\Support\Optimizer;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use RuntimeException;

class ThemeManager extends ExtensionManager
{
    /**
     * The current theme if set.
     */
    protected ?string $currentTheme = null;

    /**
     * The themes' directory.
     */
    protected string $themesPath;

    /**
     * The themes public directory for assets.
     */
    protected string $themesPublicPath;

    /**
     * Create a new ThemeManager instance.
     */
    public function __construct(Filesystem $files)
    {
        parent::__construct($files);

        $this->themesPath = resource_path('themes/');
        $this->themesPublicPath = public_path('assets/themes/');
    }

    /**
     * Load and enable the given theme.
     */
    public function loadTheme(string $theme): void
    {
        $config = config();
        $finder = view()->getFinder();

        if ($this->currentTheme !== null) {
            $paths = $finder->getPaths();
            $old = $this->path('views');
            $finder->setPaths(array_filter($paths, fn (string $path) => $path !== $old));

            $paths = $config->get('view.paths');
            $paths = array_filter($paths, fn (string $path) => $path !== $old);
            $config->set('view.paths', array_values($paths));
        }

        $this->currentTheme = $theme;
        $viewPath = $this->path('views');

        // Add theme path to view finder
        $finder->prependLocation($viewPath);
        $config->prepend('view.paths', $viewPath);

        $this->loadConfig($theme);

        if (is_dir($themeLangPath = $this->path('lang'))) {
            trans()->addNamespace('theme', $themeLangPath);
        }
    }

    public function changeTheme(?string $theme): void
    {
        Setting::updateSettings('theme', $theme);

        if ($theme !== null) {
            $this->createAssetsLink($theme);
        }
    }

    public function updateConfig(string $theme, array $config): void
    {
        $json = json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        $this->files->put($this->path('config.json', $theme), $json);

        Setting::updateSettings('themes.config.'.$theme, $config);
    }

    /**
     * Get the path of the specified theme.
     * If no theme is specified the current theme is used.
     * When no theme is specified and there is no theme enabled, this
     * will return null.
     */
    public function path(string $path = '', ?string $theme = null): ?string
    {
        if ($theme === null) {
            if (! $this->hasTheme()) {
                return null;
            }

            $theme = $this->currentTheme;
        }

        return $this->themesPath("{$theme}/{$path}");
    }

    /**
     * Get the public path of the specified theme.
     */
    public function publicPath(string $path = '', ?string $theme = null): ?string
    {
        if ($theme === null) {
            if (! $this->hasTheme()) {
                return null;
            }

            $theme = $this->currentTheme;
        }

        return $this->themesPublicPath("{$theme}/{$path}");
    }

    /**
     * Get the themes path which contains the installed themes.
     */
    public function themesPath(string $path = ''): string
    {
        return $this->themesPath.$path;
    }

    /**
     * Get the themes public path which contains the assets of the installed themes.
     */
    public function themesPublicPath(string $path = ''): string
    {
        return $this->themesPublicPath.$path;
    }

    /**
     * Get an array containing the descriptions of the installed themes.
     */
    public function findThemesDescriptions(): Collection
    {
        $directories = $this->files->directories($this->themesPath);

        $themes = [];

        foreach ($directories as $dir) {
            $description = $this->getJson($dir.'/theme.json');

            if ($description) {
                $themes[$this->files->basename($dir)] = $description;
            }
        }

        return collect($themes);
    }

    /**
     * Get the description of the given theme.
     */
    public function findDescription(string $theme): ?object
    {
        $path = $this->path('theme.json', $theme);

        $json = $this->getJson($path);

        if ($json === null) {
            return null;
        }

        // The theme folder must be the theme id
        return $theme === $json->id ? $json : null;
    }

    /**
     * Get an array containing the installed themes names.
     *
     * @return string[]
     */
    public function findThemes(): array
    {
        $paths = $this->files->directories($this->themesPath);

        return array_map(fn ($dir) => $this->files->basename($dir), $paths);
    }

    /**
     * Delete the given theme.
     */
    public function delete(string $theme): void
    {
        if ($this->findDescription($theme) === null) {
            return;
        }

        Setting::updateSettings('themes.config.'.$theme, null);

        $this->files->deleteDirectory($this->publicPath('', $theme));

        $this->files->deleteDirectory($this->path('', $theme));

        Cache::forget('updates_counts');
    }

    /**
     * Get the current theme, or null if none is active.
     */
    public function currentTheme(): ?string
    {
        return $this->currentTheme;
    }

    /**
     * Get if there is any active theme enabled.
     */
    public function hasTheme(): bool
    {
        return $this->currentTheme !== null;
    }

    public function getOnlineThemes(bool $force = false): Collection
    {
        $themes = app(UpdateManager::class)->getThemes($force);

        $installedThemes = $this->findThemesDescriptions()
            ->filter(fn ($theme) => isset($theme->apiId));

        return collect($themes)->filter(function ($theme) use ($installedThemes) {
            return ! $installedThemes->contains('apiId', $theme['id']);
        });
    }

    public function getThemesToUpdate(bool $force = false): Collection
    {
        $themes = app(UpdateManager::class)->getThemes($force);

        return $this->findThemesDescriptions()->filter(function ($theme) use ($themes) {
            $id = $theme->apiId ?? 0;

            if (! array_key_exists($id, $themes)) {
                return false;
            }

            return version_compare($themes[$id]['version'], $theme->version, '>');
        });
    }

    public function isLegacy(string $theme): bool
    {
        $description = $this->findDescription($theme);
        $apiVersion = $description->azuriom_api ?? null;

        return ! ExtensionManager::isApiSupported($apiVersion);
    }

    public function install($themeId): void
    {
        $updateManager = app(UpdateManager::class);

        $themes = $updateManager->getThemes(true);

        if (! array_key_exists($themeId, $themes)) {
            throw new RuntimeException('Cannot find theme with id '.$themeId);
        }

        $themeInfo = $themes[$themeId];

        $theme = $themeInfo['extension_id'];

        $themeDir = $this->path('', $theme);

        if (! $this->files->isDirectory($themeDir)) {
            $this->files->makeDirectory($themeDir);
        }

        $updateManager->download($themeInfo, 'themes/');
        $updateManager->extract($themeInfo, $themeDir, 'themes/');

        app(Optimizer::class)->clearViewCache();

        $this->createAssetsLink($theme);
    }

    public function readConfig(string $theme): ?array
    {
        return $this->getJson($this->path('config.json', $theme), true);
    }

    protected function loadConfig(string $theme): void
    {
        $config = setting('themes.config.'.$theme);

        if ($config === null) {
            $config = $this->readConfig($theme);

            Setting::updateSettings('themes.config.'.$theme, $config);
        }

        if ($config !== null) {
            config()?->set('theme', $config);
        }
    }

    protected function createAssetsLink(string $theme): void
    {
        if ($this->files->exists($this->publicPath('', $theme))) {
            return;
        }

        $themeAssetsPath = $this->path('assets', $theme);

        if ($this->files->exists($themeAssetsPath)) {
            Files::relativeLink($themeAssetsPath, $this->themesPublicPath($theme));
        }
    }
}
