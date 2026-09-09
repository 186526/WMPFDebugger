import { IPlatform, WmpfProcessInfo } from "./types";
import * as frida from "frida"
import * as fs from 'fs';

function searchWmpfVersionInFile(filePath: string): number {
    const buffer = fs.readFileSync(filePath);
    const binstr = buffer.toString('latin1');
    const regex = /,(?:\d+\.){3}(\d+)\x00/;
    const match = regex.exec(binstr);
    return match && match[1]
        ? Number(match[1])
        : 0;
}

export class LinuxPlatform implements IPlatform {
    async findWmpfProcess(): Promise<WmpfProcessInfo> {
        const localDevice = await frida.getLocalDevice();
        const processes = await localDevice.enumerateProcesses({
            scope: frida.Scope.Metadata,
        });
        const wmpfProcesses = processes.filter(
            (process) => process.name === "WeChatAppEx",
        );

        // The browser process is the root of the WeChatAppEx process tree,
        // i.e. the only one whose parent is not another WeChatAppEx process.
        // Picking the most frequent parent pid instead is unreliable: once
        // enough renderers are spawned under a zygote, that zygote wins and
        // frida cannot inject into it.
        const wmpfPidSet = new Set(wmpfProcesses.map((process) => process.pid));
        const wmpfProcess = wmpfProcesses.find(
            (process) => !wmpfPidSet.has(Number(process.parameters.ppid)),
        );
        if (wmpfProcess === undefined) {
            throw new Error("[frida] WeChatAppEx process not found");
        }
        const wmpfProcessPath = wmpfProcess.parameters.path as string | undefined;
        const wmpfVersion = wmpfProcessPath
            ? searchWmpfVersionInFile(wmpfProcessPath)
            : 0;
        if (wmpfVersion === 0) {
            throw new Error("[frida] error in find wmpf version");
        }
        return { pid: wmpfProcess.pid, version: wmpfVersion };
    }
}
