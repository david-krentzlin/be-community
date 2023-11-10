# frozen_string_literal: true

require 'murmurhash3/pure_ruby'
require 'fnv'
require 'bitarray'
require 'securerandom'

# an implementation of a bloom filter that is a little more sophisticated
class Bloomfilter
  attr_reader :size, :hash_rounds, :seeds

  DEFAULT_FALSE_POSITIVE_RATE = 1.0E-7
  HASH_FUNCTIONS = [
    ->(key) { MurmurHash3::PureRuby32.murmur3_32_str_hash(key) },
    ->(key) { Fnv::Hash.fnv_1a(key, size: 32) }
  ].freeze

  def initialize(expected_elements, false_positive_rate: DEFAULT_FALSE_POSITIVE_RATE)
    @size = calculate_size(expected_elements, false_positive_rate)
    @hash_rounds = calculate_hash_rounds(@size, expected_elements)
    @seeds = calculate_seeds(@hash_rounds)
    @state = BitArray.new(@size)
  end

  def add(key)
    hashes(key).each do |hash|
      @state[hash % @size] = 1
    end

    self
  end

  def member?(key)
    hashes(key).all? do |hash|
      @state[hash % @size] == 1
    end
  end

  def saturation
    @state.total_set  / @size.to_f
  end

  def hashes(key)
    @seeds.flat_map do |seed|
      HASH_FUNCTIONS.map { |hf| hf.call("#{key}_#{seed}") }
    end
  end

  # The size of the filter is m = -n ln(p) / (ln(2))^2.
  # see: https://hur.st/bloomfilter/?n=10000&p=1.0E-7&m=&k=
  def calculate_size(expected_elements, false_positive_rate)
    -((expected_elements * Math.log(false_positive_rate) / Math.log(2) ** 2)).ceil
  end

  # The optimal number of hash functions is k = m/n ln(2).
  # see: https://hur.st/bloomfilter/?n=10000&p=1.0E-7&m=&k=
  def calculate_hash_rounds(size, expected_elements)
    (size / expected_elements * Math.log(2)).ceil
  end

  # calculate seeds to "create" more hash functions
  def calculate_seeds(hash_rounds)
    (hash_rounds / HASH_FUNCTIONS.size).times.map { SecureRandom.hex }
  end

  def bytesize
    @state.size / 8
  end

  def to_s
    @state.to_s
  end

  def inspect
    "#<#{self.class.name}:#{object_id} state_size=#{size} hash_rounds=#{hash_rounds} saturation=#{saturation} bytesize=#{bytesize}>"
  end

end
