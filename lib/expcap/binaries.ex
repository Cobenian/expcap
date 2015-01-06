defmodule ExPcap.Binaries do

  @moduledoc """
  This module provides utility functions for dealing with binaries.


  """

  @doc """
  Converts a list of bytes to a binary.

  Ideally, this would be replaced by a standard elixir function, but I have not
  been able to find such a function in the standard library.

  ## Examples

      iex> ExPcap.Binaries.to_binary([1, 2, 3, 4])
      <<1, 2, 3, 4>>

  """
  @spec to_binary(list) :: binary
  def to_binary(list) do
    to_binary(list, <<>>)
  end

  @spec to_binary([], binary) :: binary
  def to_binary([], acc) do
    acc
  end

  @doc """
  Moves the contents of the list to the end of the binary.

  This will recur until it reaches the degenerate case and returns the
  accumulator (binary).

  ## Examples

      iex> ExPcap.Binaries.to_binary([3, 4], <<1, 2>>)
      #<<1, 2, 3>>
      #and then
      <<1, 2, 3, 4>>
  """
  @spec to_binary(list, binary) :: binary
  def to_binary(list, acc) do
    [h | t] = list
    to_binary(t, acc <> <<h>>)
  end

  @doc """
  Converts a binary to a list of bytes.

  ## Examples

      iex> ExPcap.Binaries.to_list(<<1, 2, 3, 4>>)
      [1, 2, 3, 4]

  """
  @spec to_list(binary) :: list
  def to_list(b) do
    to_list(b, [])
  end

  @spec to_list(<<>>, [any]) :: [any]
  def to_list(<<>>, acc) do
    Enum.reverse acc
  end

  @doc """
  Moves the bytes from the binary to the list. The order of the bytes will be
  reversed until the degenerate case is reached.

  This will recur until it reaches the degenerate case and returns the
  accumulator (list).

  ## Examples

      iex> ExPcap.Binaries.to_list(<<3, 4>>, [2, 1])
      #[3, 2, 1]
      #and then
      #[4, 3, 2, 1]
      #and then
      [1, 2, 3, 4]
  """
  @spec to_list(binary, list) :: list
  def to_list(b, acc) do
    <<a :: size(8), rest :: binary>> = b
    to_list(rest, [a | acc])
  end

  @spec reverse_binary(<<>>, binary) :: binary
  def reverse_binary(<<>>, acc) do
    acc
  end

  @doc """
  Reversed the contents of the first binary and prepends them to the second
  binary.

  This will recur until it reaches the degenerate case and returns the
  accumulator.

  ## Examples

      iex> ExPcap.Binaries.reverse_binary(<<3, 4>>, <<2, 1>>)
      #<<3, 2, 1>>
      #and then
      <<4, 3, 2, 1>>

  """
  @spec reverse_binary(binary, binary) :: binary
  def reverse_binary(<<h :: bytes-size(1), t :: binary>>, acc) do
    reverse_binary(t, h <> acc)
  end

  @doc """
  Reverses the bytes in the binary.

  ## Examples

      iex> ExPcap.Binaries.reverse_binary(<<1, 2, 3, 4>>)
      <<4, 3, 2, 1>>

  """
  @spec reverse_binary(binary) :: binary
  def reverse_binary(b) do
    reverse_binary(b, <<>>)
  end

  @doc """
  Converts the first 4 bits of the binary to an unsigned integer.

  ## Examples

      iex> ExPcap.Binaries.to_uint4(<<0xf :: size(4)>>)
      15

  """
  @spec to_uint4(binary) :: non_neg_integer
  def to_uint4(b) do
    <<n :: unsigned-integer-size(4)>> = b
    n
  end

  @doc """
  Converts the first 16 bits of the binary to an unsigned integer.

  ## Examples

      iex> ExPcap.Binaries.to_uint16(<<255, 255>>)
      65535

  """
  @spec to_uint16(binary) :: non_neg_integer
  def to_uint16(b) do
    <<n :: unsigned-integer-size(16)>> = b
    n
  end

  @doc """
  Converts the first 32 bits of the binary to an unsigned integer.

  ## Examples

      iex> ExPcap.Binaries.to_uint32(<<255, 255, 255, 255>>)
      4294967295

  """
  @spec to_uint32(binary) :: non_neg_integer
  def to_uint32(b) do
    <<n :: unsigned-integer-size(32)>> = b
    n
  end

  @doc """
  Converts the first 32 bits of the binary to a signed integer.

  ## Examples

      iex> ExPcap.Binaries.to_int32(<<255, 255, 255, 255>>)
      -1

  """
  @spec to_int32(binary) :: integer
  def to_int32(b) do
    <<n :: signed-integer-size(32)>> = b
    n
  end

  @doc """
  Converts a binary to a string that shows the bytes in the binary.

  The typical display of a binary truncates the bytes, the intent here was to
  show the entire contents of the binary.

  ## Examples

      iex> ExPcap.Binaries.to_string(<<1, 2, 3, 4>>)
      "<<1, 2, 3, 4>>"
  """
  @spec to_string(binary) :: String.t
  def to_string(b) do
    Inspect.Algebra.to_doc(b, %Inspect.Opts{width: 80})
  end

  @doc """
  Converts a binary to a 'raw' representation of the bytes.

  ## Examples

      iex> ExPcap.Binaries.to_raw(<<1, 2, 3, 4>>)
      #<<1, 2, 3, 4>>
      "... redacted ..."
  """
  @spec to_raw(binary) :: String.t
  def to_raw(_b) do
    # to_string(b)
    "... redacted ..."
  end

  @doc """
  Converts a binary to a hex representation.

  This differs from 'Base.encode16' in that it adds the leading 0x prior to the
  hex value.

  Note that the return type could be cleaned up here to only include 0-9 and a-f
  but no need to do that right now.

  ## Examples

      iex> ExPcap.Binaries.to_hex(<<255, 0>>)
      "0xFF00"

  """
  @spec to_hex(binary) :: String.t
  def to_hex(b) do
    "0x" <> Base.encode16(b)
  end

end
