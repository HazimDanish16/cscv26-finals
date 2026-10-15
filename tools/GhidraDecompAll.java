// Ghidra headless post-script: decompile every function to plain C and dump to <program>.decomp.c
// Invoked by tools/decompile.sh via analyzeHeadless -postScript
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.PrintWriter;

public class GhidraDecompAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        String outPath = getScriptArgs().length > 0 ? getScriptArgs()[0]
                : currentProgram.getExecutablePath() + ".decomp.c";
        PrintWriter out = new PrintWriter(outPath);
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            DecompileResults res = ifc.decompileFunction(f, 60, new ConsoleTaskMonitor());
            out.println("// ---- " + f.getName() + " @ " + f.getEntryPoint() + " ----");
            if (res != null && res.decompileCompleted()) {
                out.println(res.getDecompiledFunction().getC());
            } else {
                out.println("// decompile failed: " + (res != null ? res.getErrorMessage() : "null result"));
            }
            out.println();
        }
        out.close();
        println("Decompiled output written to " + outPath);
    }
}
