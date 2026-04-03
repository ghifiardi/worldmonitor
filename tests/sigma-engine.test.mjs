import { strict as assert } from 'node:assert';
import test from 'node:test';
import { normalizeEvent } from '../src/services/sigma-engine.ts';

test('normalizeEvent: passes through canonical fields unchanged', () => {
  const event = { src_ip: '10.0.0.1', dst_ip: '10.0.0.2', port: 443 };
  const result = normalizeEvent(event);
  assert.equal(result.src_ip, '10.0.0.1');
  assert.equal(result.dst_ip, '10.0.0.2');
  assert.equal(result.port, 443);
});

test('normalizeEvent: maps destination.ip to dst_ip', () => {
  const event = { 'destination.ip': '10.0.0.2', 'source.ip': '10.0.0.1' };
  const result = normalizeEvent(event);
  assert.equal(result.dst_ip, '10.0.0.2');
  assert.equal(result.src_ip, '10.0.0.1');
});

test('normalizeEvent: maps dest_ip and dst aliases', () => {
  assert.equal(normalizeEvent({ dest_ip: '1.2.3.4' }).dst_ip, '1.2.3.4');
  assert.equal(normalizeEvent({ dst: '1.2.3.4' }).dst_ip, '1.2.3.4');
});

test('normalizeEvent: maps port aliases', () => {
  assert.equal(normalizeEvent({ dport: 80 }).dst_port, 80);
  assert.equal(normalizeEvent({ sport: 12345 }).src_port, 12345);
  assert.equal(normalizeEvent({ 'destination.port': 443 }).dst_port, 443);
  assert.equal(normalizeEvent({ 'source.port': 8080 }).src_port, 8080);
});

test('normalizeEvent: maps device_id and asset_id to host_id', () => {
  assert.equal(normalizeEvent({ device_id: 'DEV-01' }).host_id, 'DEV-01');
  assert.equal(normalizeEvent({ asset_id: 'AST-02' }).host_id, 'AST-02');
});

test('normalizeEvent: maps username and login to user', () => {
  assert.equal(normalizeEvent({ username: 'admin' }).user, 'admin');
  assert.equal(normalizeEvent({ login: 'root' }).user, 'root');
});

test('normalizeEvent: maps event.action to action', () => {
  assert.equal(normalizeEvent({ 'event.action': 'login' }).action, 'login');
});

test('normalizeEvent: preserves unmapped fields as-is', () => {
  const event = { custom_field: 'value', src_ip: '10.0.0.1' };
  const result = normalizeEvent(event);
  assert.equal(result.custom_field, 'value');
  assert.equal(result.src_ip, '10.0.0.1');
});

test('normalizeEvent: canonical field wins over alias', () => {
  const event = { dst_ip: '10.0.0.1', dest_ip: '10.0.0.2' };
  const result = normalizeEvent(event);
  assert.equal(result.dst_ip, '10.0.0.1');
});
