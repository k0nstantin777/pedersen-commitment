<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit577adb9bc982451618e5bf8127432556
{
    public static $prefixLengthsPsr4 = array (
        'K' => 
        array (
            'Konstantin\\Pedersen\\' => 20,
        ),
        'E' => 
        array (
            'Elliptic\\' => 9,
        ),
        'B' => 
        array (
            'BN\\' => 3,
            'BI\\' => 3,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Konstantin\\Pedersen\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src',
        ),
        'Elliptic\\' => 
        array (
            0 => __DIR__ . '/..' . '/simplito/elliptic-php/lib',
        ),
        'BN\\' => 
        array (
            0 => __DIR__ . '/..' . '/simplito/bn-php/lib',
        ),
        'BI\\' => 
        array (
            0 => __DIR__ . '/..' . '/simplito/bigint-wrapper-php/lib',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit577adb9bc982451618e5bf8127432556::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit577adb9bc982451618e5bf8127432556::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInit577adb9bc982451618e5bf8127432556::$classMap;

        }, null, ClassLoader::class);
    }
}
