#!/bin/bash

# Fix import paths after restructuring

cd src

echo "Fixing import paths..."

# Fix enclave/ references in index.ts
find . -name "*.ts" -type f -exec sed -i "s|from './enclave/|from './|g" {} +
find . -name "*.ts" -type f -exec sed -i 's|from "./enclave/|from "./|g' {} +

# Fix ../utils/  →  ./utils/
find . -name "*.ts" -type f -exec sed -i "s|from '../utils/|from './utils/|g" {} +
find . -name "*.ts" -type f -exec sed -i 's|from "../utils/|from "./utils/|g' {} +

# Fix ../config/  →  ./config/
find . -name "*.ts" -type f -exec sed -i "s|from '../config/|from './config/|g" {} +
find . -name "*.ts" -type f -exec sed -i 's|from "../config/|from "./config/|g' {} +

# Fix ../../types  →  ./types
find . -name "*.ts" -type f -exec sed -i "s|from '../../types|from './types|g" {} +
find . -name "*.ts" -type f -exec sed -i 's|from "../../types|from "./types|g' {} +

# Fix ../../core/  →  ./core/
find . -name "*.ts" -type f -exec sed -i "s|from '../../core/|from './core/|g" {} +
find . -name "*.ts" -type f -exec sed -i 's|from "../../core/|from "./core/|g' {} +

# Fix ../../external/  →  ./external/
find . -name "*.ts" -type f -exec sed -i "s|from '../../external/|from './external/|g" {} +
find . -name "*.ts" -type f -exec sed -i 's|from "../../external/|from "./external/|g' {} +

# Fix ../external/  →  ./external/
find . -name "*.ts" -type f -exec sed -i "s|from '../external/|from './external/|g" {} +
find . -name "*.ts" -type f -exec sed -i 's|from "../external/|from "./external/|g' {} +

# Fix ../base/  →  ./external/base/  (for connectors)
find . -name "*.ts" -type f -exec sed -i "s|from '../base/|from './external/base/|g" {} +
find . -name "*.ts" -type f -exec sed -i 's|from "../base/|from "./external/base/|g' {} +

# Fix ../interfaces/  →  ./external/interfaces/
find . -name "*.ts" -type f -exec sed -i "s|from '../interfaces/|from './external/interfaces/|g" {} +
find . -name "*.ts" -type f -exec sed -i 's|from "../interfaces/|from "./external/interfaces/|g' {} +

# Fix ../repositories/  →  ./repositories/  (within services/)
find . -name "*.ts" -type f -exec sed -i "s|from '../repositories/|from './repositories/|g" {} +
find . -name "*.ts" -type f -exec sed -i 's|from "../repositories/|from "./repositories/|g' {} +

# Fix imports within connectors
cd connectors
find . -name "*.ts" -type f -exec sed -i "s|from '../alpaca-api-service'|from '../external/alpaca-api-service'|g" {} +
find . -name "*.ts" -type f -exec sed -i "s|from '../ibkr-flex-service'|from '../external/ibkr-flex-service'|g" {} +
find . -name "*.ts" -type f -exec sed -i "s|from '../ccxt-service'|from '../external/ccxt-service'|g" {} +
cd ..

# Fix imports within external/
cd external
find . -name "*.ts" -type f -exec sed -i "s|from '../../types|from '../types|g" {} +
find . -name "*.ts" -type f -exec sed -i 's|from "../../types|from "../types|g' {} +
find . -name "*.ts" -type f -exec sed -i "s|from '../../utils/|from '../utils/|g" {} +
find . -name "*.ts" -type f -exec sed -i 's|from "../../utils/|from "../utils/|g' {} +
cd ..

echo "Done fixing imports!"
