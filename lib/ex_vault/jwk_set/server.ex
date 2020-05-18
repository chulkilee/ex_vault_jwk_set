defmodule ExVault.JwkSet.CacheServer do
  @moduledoc """
  A server to cache JWK Set.
  """

  use GenServer

  require Logger

  @doc false
  defmacro __using__(opts) do
    quote location: :keep do
      def child_spec(init_arg) do
        default = %{
          id: __MODULE__,
          start: {__MODULE__, :start_link, [init_arg]}
        }

        Supervisor.child_spec(default, [])
      end

      @doc false
      def __opts__ do
        Keyword.put_new(unquote(opts), :name, __MODULE__)
      end

      @doc """
      Returns cached version of available keys.

      See also `ExVault.JwkSet.get_available_keys/2`
      """
      def get_available_keys do
        GenServer.call(Keyword.fetch!(__opts__(), :name), :get_available_keys)
      end

      def start_link(init_args) do
        GenServer.start_link(
          ExVault.JwkSet.CacheServer,
          init_args ++ Keyword.take(unquote(opts), [:module]),
          name: Keyword.fetch!(__opts__(), :name)
        )
      end
    end
  end

  @impl GenServer
  def init(args) do
    {:ok, %{module: Keyword.fetch!(args, :module)}, {:continue, :load}}
  end

  @impl GenServer
  def handle_continue(:load, state), do: get_keys(state)

  @impl GenServer
  def handle_call(:get_available_keys, _from, %{keys: keys} = state),
    do: {:reply, keys, state}

  @impl GenServer
  def handle_info(:refresh, state) do
    Logger.info("refreshing keys")

    get_keys(state)
  end

  defp get_keys(%{module: module} = state) do
    case apply(module, :get_available_keys, []) do
      {:ok, keys} ->
        {:noreply, state |> Map.put(:keys, keys)}

      {:error, error} ->
        Logger.error("failed to authenticate", error: inspect(error))
        {:stop, :normal, state}
    end
  end
end
