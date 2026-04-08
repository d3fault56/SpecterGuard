export default function LoadingSpinner() {
  return (
    <div className="flex justify-center py-12">
      <div className="text-center">
        <div className="inline-block">
          <div className="w-12 h-12 border-4 border-slate-700 border-t-blue-500 rounded-full animate-spin"></div>
        </div>
        <p className="mt-4 text-slate-400">Analyzing...</p>
      </div>
    </div>
  );
}