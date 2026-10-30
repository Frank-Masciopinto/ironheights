import { writeFileSync } from 'node:fs';
import { z } from 'zod';
import { SCHEMA_URL, ThreatModelSchema } from '../src/threatmodel/threatmodel.ts';

const schema = {
  ...z.toJSONSchema(ThreatModelSchema, { io: 'input' }),
  $id: SCHEMA_URL,
  title: 'Ironheights agent threat model (ironheights.threatmodel.yml)',
};
writeFileSync('docs/threatmodel.schema.json', JSON.stringify(schema, null, 2) + '\n');
