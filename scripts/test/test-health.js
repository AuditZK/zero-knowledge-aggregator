const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const path = require('path');

// Load proto file
const PROTO_PATH = path.join(__dirname, 'src/proto/enclave.proto');

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true
});

const enclaveProto = grpc.loadPackageDefinition(packageDefinition).enclave;

// Create insecure client (for development with GRPC_INSECURE=true)
const client = new enclaveProto.EnclaveService(
  'localhost:50051',
  grpc.credentials.createInsecure()
);

// Test HealthCheck
console.log('🏥 Testing HealthCheck...\n');

client.HealthCheck({}, (error, response) => {
  if (error) {
    console.error('❌ Error:', error.message);
    console.error('Code:', error.code);
    process.exit(1);
  }

  console.log('✅ Health Check Response:');
  console.log(JSON.stringify(response, null, 2));

  if (response.status === 0) {
    console.log('\n✅ Enclave is HEALTHY');
    console.log(`   - Enclave mode: ${response.enclave ? 'YES' : 'NO'}`);
    console.log(`   - Version: ${response.version}`);
    console.log(`   - Uptime: ${response.uptime} seconds`);
  } else {
    console.log('\n⚠️  Enclave is UNHEALTHY');
  }

  process.exit(0);
});
