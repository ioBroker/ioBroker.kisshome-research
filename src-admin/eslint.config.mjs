import config, { reactConfig } from '@iobroker/eslint-config';

// disable temporary the rule 'jsdoc/require-param' and enable 'jsdoc/require-jsdoc'
config.forEach(rule => {
    if (rule?.plugins?.jsdoc) {
        rule.rules['jsdoc/require-jsdoc'] = 'off';
        rule.rules['jsdoc/require-param'] = 'off';
    }
});

export default [
    ...config,
    ...reactConfig,
    {
        ignores: ['node_modules/**/*', 'build/**/*', 'craco.config.js', 'modulefederation.config.js'],
        files: ['src-admin/src/**/*.jsx', '**/*.tsx'],
    },
    {
        languageOptions: {
            parserOptions: {
                projectService: {
                    allowDefaultProject: ['*.mjs'],
                },
                tsconfigRootDir: import.meta.dirname,
            },
        },
    },
];
