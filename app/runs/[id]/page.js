import RunsScreen from '../../../components/RunsScreen.jsx';

export const metadata = { title: 'Run evidence' };
export const dynamic = 'force-dynamic';

export default async function RunPage({ params }) {
  const { id } = await params;
  return <RunsScreen initialRunId={id} />;
}
