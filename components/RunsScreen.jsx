import ProductSidebar from './ProductSidebar.jsx';
import RunExplorer from './RunExplorer.jsx';

export default function RunsScreen({ initialRunId = null }) {
  return (
    <>
      <a className="skip-link" href="#demo-main">Skip to demo</a>
      <div className="demo-shell">
        <ProductSidebar active="runs" />
        <RunExplorer initialRunId={initialRunId} />
      </div>
    </>
  );
}
