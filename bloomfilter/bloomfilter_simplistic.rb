# frozen_string_literal: true

require 'murmurhash3/pure_ruby'
require 'fnv'
require 'securerandom'

# Most simple bloom filter implementation to show the basic idea.
class BloomFilterSimplest
  SIZE = 2**8 # real implementations use way bigger states
  SEEDS = 5   # real implementations use more seeds and calculate them dynamically

  def initialize
    @seeds = SEEDS.times.map { SecureRandom.hex }
    # we'll (ab)use bignum to store the state of the filter
    @state = 0
  end

  def add(key)
    hashes(key).each do |hash|
      # set bit at position hash % SIZE
      @state |= 1 << (hash % SIZE)
    end
    self
  end

  def member?(key)
    hashes(key).all? do |hash|
      @state[hash % SIZE] == 1
    end
  end

  def hashes(key)
    @seeds.flat_map do |seed|
      [
        MurmurHash3::PureRuby32.murmur3_32_str_hash("#{key}_#{seed}"),
        FNV.new.fnv1a_32("#{key}_#{seed}")
      ]
    end
  end

  def saturation
    # real implementations likely use the kernighan's algorithm to count the bits fast
    @state.to_s(2).count('1') / SIZE.to_f
  end

  def to_s
    @state.to_s(2).rjust(SIZE, '0')
  end
end
