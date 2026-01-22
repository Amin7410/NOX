const nodeExternals = require('webpack-node-externals');

module.exports = function (options, webpack) {
    return {
        ...options,
        externals: [
            nodeExternals({
                allowlist: [/^@nox\/(?!database)/], // Bundle @nox/* EXCEPT @nox/database
            }),
            // Explicitly mark Prisma as external
            '@prisma/client',
            '.prisma/client',
        ],
    };
};
