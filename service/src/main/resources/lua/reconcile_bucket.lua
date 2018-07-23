-- keys: dest_bucket, dest_bucket_adds, dest_bucket_dels
-- argv: ..addresses

local dest_bucket      = KEYS[1]
local dest_bucket_adds = KEYS[2]
local dest_bucket_dels = KEYS[3]

local old_addresses = {}
for _, address in ipairs(redis.call("SMEMBERS", dest_bucket)) do
  old_addresses[address] = true
end

for _, address in ipairs(ARGV) do
  old_addresses[address] = nil

  if 0 == redis.call("SISMEMBER", dest_bucket, address) then
    redis.call("SADD", dest_bucket_adds, address)
    redis.call("SADD", dest_bucket, address)
  end
end

for address, _ in ipairs(old_addresses) do
  redis.call("SMOVE", dest_bucket, dest_bucket_dels, address)
end
