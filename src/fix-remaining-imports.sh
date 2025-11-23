#!/bin/bash

# Fix core/repositories imports
cd core/repositories
sed -i "s|from './types|from '../../types|g" *.ts
sed -i "s|from '../services/encryption-service'|from '../../services/encryption-service'|g" *.ts
cd ../..

# Fix core/services imports
cd core/services
sed -i "s|from './types|from '../../types|g" *.ts
sed -i "s|from './external/|from '../../external/|g" *.ts
sed -i "s|from './repositories/|from '../repositories/|g" *.ts
sed -i "s|from './trade-sync-service'|from '../../services/trade-sync-service'|g" *.ts
sed -i "s|from './equity-snapshot-aggregator'|from '../../services/equity-snapshot-aggregator'|g" *.ts
cd ../..

# Fix services imports
cd services
sed -i "s|from './types|from '../types|g" *.ts
sed -i "s|from './repositories/|from '../repositories/|g" *.ts
sed -i "s|from './external/|from '../external/|g" *.ts
sed -i "s|from './universal-connector-cache.service'|from '../core/services/universal-connector-cache.service'|g" *.ts
sed -i "s|from '../../utils/logger.service'|from '../utils/logger.service'|g" *.ts
sed -i "s|from '../../types/snapshot-breakdown'|from '../types/snapshot-breakdown'|g" *.ts
cd ..

# Fix repositories/enclave-repository.ts imports  
cd repositories
sed -i "s|from './types|from '../types|g" *.ts
sed -i "s|from '../../utils/logger'|from '../utils/logger'|g" *.ts
cd ..

# Fix external/ imports
cd external
sed -i "s|from './utils/logger.service'|from '../utils/logger.service'|g" *.ts
cd ..

# Fix external/factories imports
cd external/factories
sed -i "s|from './external/|from '../../external/|g" *.ts
sed -i "s|from './types'|from '../../types'|g" *.ts
sed -i "s|from '../utils/logger.service'|from '../../utils/logger.service'|g" *.ts
sed -i "s|from '../connectors/|from '../../connectors/|g" *.ts
cd ../..

echo "Done!"
