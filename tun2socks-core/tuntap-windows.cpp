#include <tuntap.h>
#include <tap-windows.h>
#include <Windows.h>
#include <assert.h>

#undef IP_STATS
#undef ICMP_STATS
#undef TCP_STATS
#undef UDP_STATS
#undef IP6_STATS

#include <iphlpapi.h>

#pragma comment(lib, "WinMM.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "WS2_32.lib")

BOOL _synchronized_deviceiocontrol(
	_In_ HANDLE hDevice,
	_In_ DWORD dwIoControlCode,
	_In_reads_bytes_opt_(nInBufferSize) LPVOID lpInBuffer,
	_In_ DWORD nInBufferSize,
	_Out_writes_bytes_to_opt_(nOutBufferSize, *lpBytesReturned) LPVOID lpOutBuffer,
	_In_ DWORD nOutBufferSize,
	_Out_opt_ LPDWORD lpBytesReturned
) {
	BOOL result = false;
	OVERLAPPED overlapped{ 0 };
	overlapped.hEvent = CreateEventA(NULL, false, false, NULL);
	if (!DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, &overlapped)) {
		if (GetLastError() == ERROR_IO_PENDING) {
			WaitForSingleObject(overlapped.hEvent, INFINITE);
			CloseHandle(overlapped.hEvent);
			result = (overlapped.Internal == ERROR_SUCCESS);
		}
		else
			result = false;
	}
	else
		result = true;
	CloseHandle(overlapped.hEvent);
	return result;
}

namespace tun2socks {
	TUNDevice::TUNDevice(boost::asio::io_context& ctx, const TUNAdapter& adapter)
		: _ctx(ctx), _tun_handle(adapter.hd), _adapter(adapter) {}

	int TUNDevice::tap_set_address() {
		int up = 1;
		int out_len;
		if (!_synchronized_deviceiocontrol(_tun_handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS, &up, 4, &up, 4, (LPDWORD)&out_len))
			return GetLastError();
		IPADDR address[3] = {
			_adapter.ip,
			_adapter.network,
			_adapter.mask
		};
		if (!_synchronized_deviceiocontrol(_tun_handle, TAP_WIN_IOCTL_CONFIG_TUN, &address, sizeof(address), &address, sizeof(address), (LPDWORD)&out_len))
			return GetLastError();
		char cmd[1024];
		// To achieve this with Windows API is too painful :(.
		// May change in the future?
		snprintf(cmd, 1024, "netsh interface ip set address %d static %s %s", _adapter.index, 
			get_address_string(_adapter.ip).c_str(), get_address_string(_adapter.mask).c_str());
		return /*system("ipconfig /flushdns")*/system(cmd);
	}

    void TUNDevice::start_read(const std::function<void(std::shared_ptr<Request>)>& success, const std::function<void(const boost::system::error_code&)>& fail) {
        auto packet = std::make_shared<Request>();
        memset(&packet->overlapped, 0, sizeof(OVERLAPPED));
        packet->overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        packet->buf = std::shared_ptr<pbuf>(pbuf_alloc(pbuf_layer::PBUF_RAW, 1500, pbuf_type::PBUF_RAM), [](pbuf* p) {
            if (p)
                pbuf_free(p);
        });
        auto afo = std::make_shared<boost::asio::windows::object_handle>(_ctx, packet->overlapped.hEvent);
        auto fwai = [this, afo, packet, fail, success](const boost::system::error_code& err) {
            afo->close();
            if (!err) {
                if (success != NULL)
                    success(packet);
                start_read(success, fail);
            }
            else {
                if (fail != NULL)
                    fail(err);
            }
        };
        if (ReadFile(_tun_handle, packet->buf->payload, packet->buf->len, &packet->transfered, &packet->overlapped)) {
            boost::system::error_code ec;
            fwai(ec);
        }
        else {
            afo->async_wait(fwai);
        }
    }

	void TUNDevice::do_write(std::unique_ptr<u_char[]>&& buffer, size_t len, std::function<void()> success, std::function<void(const boost::system::error_code&)> fail) {
		auto overlapped = std::make_shared<OVERLAPPED>(OVERLAPPED{ 0 });
		overlapped->hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

        std::shared_ptr<u_char[]> packet = std::move(buffer);
		auto afo = std::make_shared<boost::asio::windows::object_handle>(_ctx, overlapped->hEvent);
        auto fwait = [this, packet, overlapped, afo, success, fail](const boost::system::error_code& err) {
            afo->close();
            if (!err) {
                // do nothing.
                if (success != NULL)
                    success();
            }
            else {
                if (fail != NULL)
                    fail(err);
            }
        };
        DWORD transfered;
        if (WriteFile(_tun_handle, packet.get(), len, &transfered, overlapped.get())) {
            boost::system::error_code ec;
            fwait(ec);
        }
        else {
            afo->async_wait(fwait);
        }
	}
}

std::vector<std::string> search_instance_id(std::function<bool(const std::string&)>&& istap) {
	std::vector<std::string> result;
	auto close_key_deleter = [](HKEY* p) {RegCloseKey(*p); };
	HKEY adapters_key;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTER_KEY, NULL, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &adapters_key))
		return result;
	DWORD max_subkey_len;
	DWORD nsubkeys;
	std::unique_ptr<HKEY, decltype(close_key_deleter)> p_adapters_key(&adapters_key, close_key_deleter);
	if (RegQueryInfoKeyA(adapters_key, NULL, NULL, NULL, &nsubkeys, &max_subkey_len, NULL, NULL, NULL, NULL, NULL, NULL))
		return result;
	auto subkey_buffer = std::make_unique<u_char[]>(max_subkey_len);
	for (DWORD i = 0; i < nsubkeys; i++) {
		if (RegEnumKeyA(*p_adapters_key, i, (LPSTR)(subkey_buffer.get()), max_subkey_len))
			continue;
		HKEY subkey;
		std::unique_ptr<HKEY, decltype(close_key_deleter)> p_subkey(&subkey, close_key_deleter);
		if (RegOpenKeyExA(*p_adapters_key, (LPSTR)(subkey_buffer.get()), NULL, KEY_QUERY_VALUE, p_subkey.get()))
			continue;
		DWORD max_value_len;
		if (RegQueryInfoKeyA(*p_subkey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &max_value_len, NULL, NULL))
			continue;
		auto value_buffer = std::make_unique<u_char[]>(max_value_len);
		DWORD bytes_read;
		if (!RegGetValueA(*p_subkey, NULL, "ComponentId", RRF_RT_REG_SZ, NULL, value_buffer.get(), &bytes_read)) {
			std::string cid((char*)(value_buffer.get()));
			if (istap(cid)) {
				bytes_read = max_value_len;
				if (!RegGetValueA(*p_subkey, NULL, "NetCfgInstanceId", RRF_RT_REG_SZ, NULL, value_buffer.get(), &bytes_read)) {
					result.emplace_back((char*)(value_buffer.get()));
				}
			}
		}
	}
	return result;
}

std::vector<TUNAdapter> get_adpaters(const std::vector<std::string>& ids) {
	std::vector<TUNAdapter> result;
	ULONG buffer_len = sizeof(IP_ADAPTER_INFO);
	auto buffer = std::make_unique<char[]>(sizeof(IP_ADAPTER_INFO));
	if (GetAdaptersInfo((PIP_ADAPTER_INFO)(buffer.get()), &buffer_len)) {
		buffer.reset();
		buffer = std::make_unique<char[]>(buffer_len);
	}
	if (GetAdaptersInfo((PIP_ADAPTER_INFO)(buffer.get()), &buffer_len))
		return result;
	auto padapter = (PIP_ADAPTER_INFO)buffer.get();
	while (padapter) {
		auto it = std::find(ids.begin(), ids.end(), padapter->AdapterName);
		if (it != ids.end()) {
			result.emplace_back();
			auto& adapter = *(result.rbegin());
			adapter.hd = TUN_INVALID_HANDLE;
			memcpy(adapter.dev_id, it->c_str(), it->length() + 1);
			memcpy(adapter.dev_name, padapter->Description, strlen(padapter->Description) + 1);
			adapter.ip = inet_addr(padapter->IpAddressList.IpAddress.String);
			adapter.mask = inet_addr(padapter->IpAddressList.IpMask.String);
			adapter.network = adapter.mask & adapter.ip;
			adapter.index = padapter->Index;
		}
		padapter = padapter->Next;
	}
	return result;
}

size_t get_tuns(TUNAdapter* buffer, size_t len) {
	auto taps_id = search_instance_id([](const std::string& tap_name) {return tap_name.compare(0, 3, "tap") == 0; });
	auto adapters = get_adpaters(taps_id);
	if (adapters.size() > len)
		return -1;
	else {
		for (size_t i = 0; i < adapters.size(); i++)
			buffer[i] = adapters[i];
		return adapters.size();
	}
}

void _wassert_fcb(
	wchar_t const* _Message,
	wchar_t const* _File,
	unsigned int _Line
)
{
	wchar_t buffer[8096];
	wsprintfW(buffer, L"assert: %s:%u\n%s\n", _File, _Line, _Message);
	OutputDebugStringW(buffer);
}

void _assert_fcb(
	char const* _Message,
	char const* _File,
	unsigned int _Line
)
{
	char buffer[8096];
	wsprintfA(buffer, "assert: %s:%u\n%s\n", _File, _Line, _Message);
	OutputDebugStringA(buffer);
}

void _attach_to_fcb(void* pfn, void* fcb) {
	DWORD flOldProtect = 0;
	VirtualProtect(pfn, 5, PAGE_EXECUTE_READWRITE, &flOldProtect);

	char* pbuf = (char*)pfn;
	pbuf[0] = '\xE9';
	*(int*)&pbuf[1] = (char*)fcb - pbuf - 5;
}

TUNAdapter* open_tun(TUNAdapter* adapter) {
	_attach_to_fcb(_wassert, _wassert_fcb);
	_attach_to_fcb(GetProcAddress(LoadLibrary(TEXT("ucrtbased.dll")), "_assert"), _assert_fcb);

	if (adapter == NULL) {
		TUNAdapter tuns[32];
		auto size = get_tuns(tuns, 32);
		if (size == 0)
			return NULL;
		else
			adapter = &tuns[0];
	}
	std::stringstream ss;
	ss << USERMODEDEVICEDIR;
	ss << adapter->dev_id;
	ss << TAP_WIN_SUFFIX;
	adapter->hd = CreateFileA(
		ss.str().c_str(),
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_SYSTEM,
		NULL);
	return new TUNAdapter(*adapter);
}

void delete_tun(TUNAdapter* adapter) {
	if (adapter != NULL)
		delete adapter;
}