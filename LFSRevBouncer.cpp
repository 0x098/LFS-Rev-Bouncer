#define WIN32_LEAN_AND_MEAN

#include <thread>
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <functional>

#define sleep( x ) std::this_thread::sleep_for(std::chrono::milliseconds(x));
#define log( x ) std::cout <<  x  << "\n";
#define wlog(x) std::wcout << x << "\n";

uint8_t AOB[] = { 0x88,0x0D,0,0,0,0,0x0F,0x44,0xC1,0xA2,0,0,0,0,0x8B,0xC6,0xA3,0,0,0,0,0x8B,0x0D,0,0,0,0,0x8B,0x15,0,0,0,0,0x3B,0xF1,0x75,0x23 };
bool MASK[] = { 1,1,0,0,0,0,1,1,1,1,0,0,0,0,1,1,1,0,0,0,0,1,1,0,0,0,0,1,1,0,0,0,0,1,1,1,1 };
uint8_t offset = 23;

const wchar_t * G = L"LFS.exe";

uint64_t pid = 0;
HANDLE proc;

uint64_t maxRPM = 0x1CF4;
uint64_t rpmOffset = 0x1D50;
uint64_t engineOnOff = 0x1D60;

struct EDAT { // engine data
  float RPM; // what it is
  float SmoothedEngineRev; // what u see visually
  float GasPedalFloat; // how much u pressing the gasser
  int garbage; // probably sound related
  int EngineState; // if engine on or off
};

uint64_t reads = 0;
BOOL rpc( HANDLE proc, LPCVOID addr, LPVOID out, size_t size, size_t * nrob ) {
  reads++;
  return ReadProcessMemory( proc, addr, out, size, nrob );
}

wchar_t readspersecond[ 64 ];
uint64_t lastread = 0;
void readToTitle( uint64_t * reads, uint64_t * lastread ) {
  //swprintf_s()
  while( 1 ) {
    //log( ( ( *reads - *lastread ) * 4 ) );
    swprintf_s( readspersecond, 64, L"reads per second: %llu", ( ( *reads - *lastread ) * 4 ) );
    *lastread = *reads;
    SetConsoleTitle( readspersecond );
    sleep( 250 );
  }
}


template <typename T>
void read( uint64_t addr, T * out ) {
  auto ret = rpc( proc, reinterpret_cast< void * >( addr ), out, sizeof( T ), 0 );
  if( ret == 0 ) {
    log( "read status:" << ret );
    log( GetLastError() );
  }
}
template <typename T>
T read( uint64_t addr ) {
  T B {0};
  auto ret = rpc( proc, reinterpret_cast< void * >( addr ), &B, sizeof( T ), 0 );
  if( ret == 0 ) {
    log( "read status:" << ret );
    log( GetLastError() );
  }
  return B;
}

#define MBSZ 4096
struct CMEM {
  uint8_t d[ MBSZ ];
};

/*v settings v*/

float threshold = 10; // upper limit to bounce back from
float amount = 95; // how far to bounce back
bool keepEngineOn = true; // keep engine on at all times? ( this excludes bottom variable if true )
float engineMinRev = 100; // how small to ignore when engine is off ( if rpm below this the engine shuts off successfully )

/*^ settings ^*/


int main() {
  std::thread titlemanager( readToTitle, &reads, &lastread );
  titlemanager.detach();

  INPUT toggleEngine[ 2 ] = {};
  toggleEngine[ 0 ].type = INPUT_KEYBOARD;
  toggleEngine[ 0 ].ki.wVk = 'I';
  toggleEngine[ 1 ].type = INPUT_KEYBOARD;
  toggleEngine[ 1 ].ki.wVk = 'I';
  toggleEngine[ 1 ].ki.dwFlags = KEYEVENTF_KEYUP;

  auto snap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
  auto * entr = new PROCESSENTRY32();
  entr->dwSize = sizeof( PROCESSENTRY32 );
  pid = 0;
  while( Process32Next( snap, entr ) ) {
    if( wcscmp( entr->szExeFile, G ) == 0 ) {
      pid = entr->th32ProcessID;
      break;
    }
  }
  CloseHandle( snap );
  auto s2 = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pid );
  delete entr;
  auto * e2 = new MODULEENTRY32();
  e2->dwSize = sizeof( MODULEENTRY32 );
  uint64_t base = 0;
  uint64_t size = 0;
  while( Module32Next( s2, e2 ) ) {
    if( wcscmp( e2->szModule, G ) == 0 ) {
      base = ( uint64_t ) e2->modBaseAddr;
      size = ( uint64_t ) e2->modBaseSize;
      wlog( e2->szModule );
      break;
    }
  }
  std::wcout << std::hex;
  proc = OpenProcess( PROCESS_ALL_ACCESS, 0, pid );
  uint64_t D = 0;

  CMEM temp { };

  std::cout << std::hex;

  uint64_t c = 0;

  bool match = false;
  int best = 0;
  uint64_t bestAddr = 0;
  while( !match && ( c * MBSZ ) < size ) {
    read( base + c * MBSZ, &temp );
    for( size_t i = 0; i < sizeof( temp ); i++ ) {
      for( size_t j = 0; j < sizeof( AOB ); j++ ) {
        if( MASK[ j ] == 0 ) {
          continue;
        } else if( AOB[ j ] != temp.d[ i + j ] ) {
          break;
        } else {
          if( best < j ) { // if match
            best = j;
            bestAddr = base + c * MBSZ + i;
          }
          if( j > 0 && j == ( sizeof( temp ) - i - 1 ) ) {
            read( base + c * MBSZ + i, &temp );
            for( size_t k = 0; k < sizeof( temp ); k++ ) {
              for( size_t l = 0; l < sizeof( AOB ); l++ ) {
                if( MASK[ l ] == 0 ) {
                  continue;
                } else if( AOB[ l ] != temp.d[ k + l ] ) {
                  break;
                } else {
                  if( best < l ) { // if match
                    best = l;
                    bestAddr = base + c * MBSZ + i;
                  }
                }
              }
            }
          }
        }
      }
    }
    c++;
  }
  log( "found addr?: " << std::hex << bestAddr );

  uint32_t ptr = read<uint32_t>( bestAddr + offset );
  log( ptr );

  uint32_t car = read<uint32_t>( ptr );
  log( car );
  EDAT E { };
  float MAXRPM = 0;

  DWORD fpid = 0;
  HWND ghwnd {};
  while( 1 ) {
    sleep( 1 );
    HWND hwnd = GetForegroundWindow();
    GetWindowThreadProcessId( hwnd, &fpid );
    if( fpid == pid ) {
      ghwnd = hwnd;
    }
    if( !ghwnd )
      continue;

    uint32_t car = read<uint32_t>( ptr );
    if( car == 0 )
      continue;
    read( car + maxRPM, &MAXRPM );
    read( car + rpmOffset, &E );
    if( E.EngineState == 1 ) {
      if( E.RPM > ( MAXRPM - threshold ) ) {
        //SendInput( 1, &toggleEngine[ 0 ], sizeof( INPUT ) ); // uncomment these if times are rough
        PostMessage( ghwnd, WM_KEYDOWN, 'I', 0 );
        sleep( 5 );
        PostMessage( ghwnd, WM_KEYUP, 'I', 0 );
        //SendInput( 1, &toggleEngine[ 1 ], sizeof( INPUT ) );
      }
    } else { // engine off
      if( E.RPM < ( MAXRPM - amount ) ) {
        if( !keepEngineOn && E.RPM < engineMinRev )
          continue;
        PostMessage( ghwnd, WM_KEYDOWN, 'I', 0 );
        //SendInput( 1, &toggleEngine[ 0 ], sizeof( INPUT ) );
        sleep( 5 );
        PostMessage( ghwnd, WM_KEYUP, 'I', 0 );
        //SendInput( 1, &toggleEngine[ 1 ], sizeof( INPUT ) );
      }
    }
  }
}
